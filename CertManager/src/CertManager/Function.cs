using System.Text;
using Amazon.CertificateManager;
using Amazon.CertificateManager.Model;
using Amazon.DynamoDBv2;
using Amazon.DynamoDBv2.DocumentModel;
using Amazon.Lambda.APIGatewayEvents;
using Amazon.Lambda.CloudWatchEvents.ScheduledEvents;
using Amazon.Lambda.Core;
using Amazon.ResourceGroupsTaggingAPI;
using Amazon.ResourceGroupsTaggingAPI.Model;
using Amazon.SimpleSystemsManagement;
using Amazon.SimpleSystemsManagement.Model;
using Certify.ACME.Anvil;
using Certify.ACME.Anvil.Acme;
using Org.BouncyCastle.Asn1.X509;
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

    public async Task<APIGatewayHttpApiV2ProxyResponse> WellKnownHandler(APIGatewayHttpApiV2ProxyRequest request, ILambdaContext context)
    {
        var pathParts = request.RawPath.Split("/");
        var token = pathParts[^1];
        context.Logger.LogInformation($"Fetching token: {token}");
        var data = await _table.GetItemAsync(token);
        if (data == null)
        {
            return new APIGatewayHttpApiV2ProxyResponse
            {
                StatusCode = 404,
                Headers = new Dictionary<string, string>
                {
                    {"Content-Type", "text/plain"}  
                },
                Body = "Not found"
            };
        }
        return new APIGatewayHttpApiV2ProxyResponse
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
        await _issuer.Init(context.Logger);
        var (cert, certKey) = await _issuer.OrderCertificate(request.Domains);
        await SaveCert(context.Logger, certName, cert, certKey);
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
        await _issuer.Init(context.Logger);
        await foreach (var resourceTagMapping in resources)
        {

            var ariCertId = resourceTagMapping.Tags.Find((t) => t.Key == "ARICertId")?.Value;

            if (ariCertId == null)
            {
                var certInfo = await _acmClient.GetCertificateAsync(resourceTagMapping.ResourceARN);
                var certParser = new X509CertificateParser();
                var oldCert = certParser.ReadCertificate(Encoding.ASCII.GetBytes(certInfo.Certificate));
                ariCertId = ComputeAriCertId(oldCert);
            }
            
            var certName = resourceTagMapping.Tags.Find((t) => t.Key == "Name")?.Value;
            if (certName == null)
            {
                context.Logger.LogWarning("Found certificate without Name: " + resourceTagMapping.ResourceARN);
                continue;
            }
            
            context.Logger.LogInformation("Checking renewal for cert: " + resourceTagMapping.ResourceARN + " (" + certName + ")");

            if(!await _issuer.ShouldRenew(ariCertId)) continue;

            var names = certName.Split(":");
            context.Logger.Log($"Renewing certificate for {certName}");
            var (cert, certKey) = await _issuer.OrderCertificate(names, ariCertId);
            await SaveCert(context.Logger, certName, cert, certKey, resourceTagMapping.ResourceARN);
        }
    }

    private static string ComputeAriCertId(X509Certificate cert)
    {
        var aki = AuthorityKeyIdentifier.GetInstance(cert.GetExtensionParsedValue(X509Extensions.AuthorityKeyIdentifier));
        var akiB64 = Convert.ToBase64String(aki.KeyIdentifier.GetOctets()).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var sn = cert.SerialNumber.ToByteArray();
        var snB64 = Convert.ToBase64String(sn).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        return $"{akiB64}.{snB64}";
    }

    private async Task SaveCert(ILambdaLogger log, string certName, CertificateChain cert, IKey certKey, string? certArn = null)
    {
        var certParser = new X509CertificateParser();
        var parsedCert = certParser.ReadCertificate(cert.Certificate.ToDer());
        var ariCertId = ComputeAriCertId(parsedCert);
        var importRes = await _acmClient.ImportCertificateAsync(new ImportCertificateRequest
        {
            CertificateArn = certArn,
            Certificate = new MemoryStream(Encoding.UTF8.GetBytes(cert.Certificate.ToPem())),
            CertificateChain = new MemoryStream(Encoding.UTF8.GetBytes(CertChainOnly(cert))),
            PrivateKey = new MemoryStream(Encoding.UTF8.GetBytes(certKey.ToPem())),
            Tags = {
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
                    Key = "ARICertID",
                    Value = ariCertId
                }
            }
        });
        log.LogInformation("Imported certificate: " + importRes.CertificateArn);
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