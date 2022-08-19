using System.Text;
using Amazon.CertificateManager;
using Amazon.CertificateManager.Model;
using Amazon.DynamoDBv2;
using Amazon.DynamoDBv2.DocumentModel;
using Amazon.Lambda.ApplicationLoadBalancerEvents;
using Amazon.Lambda.CloudWatchEvents.ScheduledEvents;
using Amazon.Lambda.Core;
using Amazon.ResourceGroupsTaggingAPI;
using Amazon.ResourceGroupsTaggingAPI.Model;
using Amazon.SimpleSystemsManagement;
using Amazon.SimpleSystemsManagement.Model;
using Certes;
using Certes.Acme;
using Certes.Pkcs;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.X509;
using Tag = Amazon.CertificateManager.Model.Tag;

// Assembly attribute to enable the Lambda function's JSON input to be converted into a .NET class.
[assembly: LambdaSerializer(typeof(Amazon.Lambda.Serialization.SystemTextJson.DefaultLambdaJsonSerializer))]

namespace CertManager;

public class Function
{
    private readonly CertificateIssuance _issuer;
    private readonly AmazonCertificateManagerClient _acmClient;
    private readonly AmazonResourceGroupsTaggingAPIClient _taggingClient;
    private readonly string _createdByTag;
    private readonly Table _table;

    public Function()
    {
        var email = Environment.GetEnvironmentVariable("ACME_EMAIL");
        if (email == null)
        {
            throw new Exception("ACME email is required");
        }
        _acmClient = new AmazonCertificateManagerClient();
        _taggingClient = new AmazonResourceGroupsTaggingAPIClient();
        _table = Table.LoadTable(new AmazonDynamoDBClient(), Environment.GetEnvironmentVariable("TABLE_ARN"));
        _createdByTag = $"LambdaCertManager-{Environment.GetEnvironmentVariable("INSTALLATION_ID")}";
        var keyPath = $"/{Environment.GetEnvironmentVariable("PARAMETER_PREFIX")}/acme-key";
        var ssmClient = new AmazonSimpleSystemsManagementClient();
        var keyParam = ssmClient.GetParameterAsync(new GetParameterRequest
        {
            Name = keyPath,
            WithDecryption = true
        });
        _issuer = new CertificateIssuance(
            email, 
            "true".Equals(Environment.GetEnvironmentVariable("LETSENCRYPT_STAGING")),
            KeyFactory.FromPem(Encoding.UTF8.GetString(Convert.FromBase64String(keyParam.Result.Parameter.Value))),
            _table
        );
    }

    public async Task<ApplicationLoadBalancerResponse> WellKnownHandler(ApplicationLoadBalancerRequest request, ILambdaContext context)
    {
        var pathParts = request.Path.Split("/");
        var token = pathParts[^1];
        Console.Out.WriteLine(token);
        var data = await _table.GetItemAsync(token);
        if (data == null)
        {
            return new ApplicationLoadBalancerResponse
            {
                StatusCode = 404,
                Headers = new Dictionary<string, string>
                {
                    {"Content-Type", "text/plain"}  
                },
                Body = "Not found"
            };
        }
        return new ApplicationLoadBalancerResponse
        {
            StatusCode = 200,
            Headers = new Dictionary<string, string>
            {
                {"Content-Type", "text/plain"}  
            },
            Body = data["response"]
        };
    }

    public async Task AddCertificate(NewCertRequest request, ILambdaContext context)
    {
        Array.Sort(request.Domains);
        var certName = string.Join(":", request.Domains);
        var existingCerts = await _taggingClient.GetResourcesAsync(new GetResourcesRequest()
        {
            ResourceTypeFilters = { "acm:certificate" },
            TagFilters =
            {
                new TagFilter
                {
                    Key = "CreatedBy",
                    Values = { _createdByTag }
                },
                new TagFilter
                {
                    Key = "Name",
                    Values = { certName }
                }
            }
        });
        if (existingCerts.ResourceTagMappingList.Count > 0)
        {
            context.Logger.Log($"Existing certificate exists for {certName} ({existingCerts.ResourceTagMappingList[0].ResourceARN})");
            return;
        }
    
        context.Logger.Log($"Provisioning certificate for {certName}");
        _issuer.Init();
        var (cert, certKey) = await _issuer.OrderCertificate(request.Domains);
        await SaveCert(certName, cert, certKey);
    }

    public async Task RenewCertificates(ScheduledEvent request, ILambdaContext context)
    {
        var resources = _taggingClient.Paginators.GetResources(new GetResourcesRequest()
        {
            ResourceTypeFilters = { "acm:certificate" },
            TagFilters =
            {
                new TagFilter
                {
                    Key = "CreatedBy",
                    Values = { _createdByTag }
                }
            }
        }).ResourceTagMappingList;
        _issuer.Init();
        await foreach (var resourceTagMapping in resources)
        {

            var expiresAtStr = resourceTagMapping.Tags.Find((t) => t.Key == "ExpiresAt")?.Value;

            if (expiresAtStr == null)
            {
                context.Logger.LogWarning("Found certificate without ExpiresAt: " + resourceTagMapping.ResourceARN);
                continue;
            }

            var expiresAt = DateTime.Parse(expiresAtStr);
            if (expiresAt >= DateTime.Now.AddDays(30)) continue;
            
            var certName = resourceTagMapping.Tags.Find((t) => t.Key == "Name")?.Value;
            if (certName == null)
            {
                context.Logger.LogWarning("Found certificate without Name: " + resourceTagMapping.ResourceARN);
                continue;
            }

            var names = certName.Split(":");
            context.Logger.Log($"Renewing certificate for {certName}");
            var (cert, certKey) = await _issuer.OrderCertificate(names);
            await SaveCert(certName, cert, certKey, resourceTagMapping.ResourceARN);
        }
    }

    private async Task SaveCert(string certName, CertificateChain cert, IKey certKey, string? certArn = null)
    {
        var certParser = new X509CertificateParser();
        var parsedCert = certParser.ReadCertificate(cert.Certificate.ToDer());
        var importRes = await _acmClient.ImportCertificateAsync(new ImportCertificateRequest
        {
            CertificateArn = certArn,
            Certificate = new MemoryStream(Encoding.UTF8.GetBytes(cert.Certificate.ToPem())),
            CertificateChain = new MemoryStream(Encoding.UTF8.GetBytes(CertChainOnly(cert))),
            PrivateKey = new MemoryStream(Encoding.UTF8.GetBytes(certKey.ToPem()))
        });
        await _acmClient.AddTagsToCertificateAsync(new AddTagsToCertificateRequest
        {
            CertificateArn = importRes.CertificateArn,
            Tags =
            {
                new Tag
                {
                    Key = "CreatedBy",
                    Value = _createdByTag
                },
                new Tag
                {
                    Key = "Name",
                    Value = certName
                },
                new Tag
                {
                    Key = "ExpiresAt",
                    Value = parsedCert.NotAfter.ToString("s")
                }
            }
        });
    }

    private static string CertChainOnly(CertificateChain chain)
    {
        using var writer = new StringWriter();
        
        var certParser = new X509CertificateParser();
        var pemWriter = new PemWriter(writer);
        foreach (var issuer in chain.Issuers)
        {
            var cert = certParser.ReadCertificate(issuer.ToDer());
            pemWriter.WriteObject(cert);
        }

        return writer.ToString();
    }
}