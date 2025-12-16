using Amazon.DynamoDBv2.DocumentModel;
using Amazon.DynamoDBv2.Model;
using Amazon.Lambda.Core;
using Certify.ACME.Anvil;
using Certify.ACME.Anvil.Acme;
using Certify.ACME.Anvil.Acme.Resource;

namespace CertManager;

public class CertificateIssuance
{
    private readonly string _email;
    private readonly AcmeContext _acme;
    private static readonly HttpClient Client = new HttpClient();
    private readonly Table _table;
    private ILambdaLogger _logger;

    public CertificateIssuance(string email, bool staging, IKey accountKey, Table table)
    {
        _acme = new AcmeContext(staging ? WellKnownServers.LetsEncryptStagingV2 : WellKnownServers.LetsEncryptV2, accountKey);
        _email = email;
        _table = table;
    }

    public async Task Init(ILambdaLogger contextLogger)
    {
        await _acme.NewAccount(_email, true);
        _logger = contextLogger;
    }

    public async Task<bool> ShouldRenew(string certId)
    {
        var renewalInfo = await _acme.GetRenewalInfo(certId);
        if (!renewalInfo.SuggestedWindow.Start.HasValue || !renewalInfo.SuggestedWindow.End.HasValue)
        {
            // per the specs this should never happen
            _logger.LogInformation("No renewal window suggested");
            return false;
        }
        if (renewalInfo.ExplanationURL != null)
        {
            _logger.LogInformation($"Renewal Explanation: {renewalInfo.ExplanationURL}");
        }
        var difference = renewalInfo.SuggestedWindow.End.Value.Subtract(renewalInfo.SuggestedWindow.Start.Value);
        var now = DateTimeOffset.UtcNow;
        var randomSlot = new Random().NextDouble();
        var scheduledRenewalTime = renewalInfo.SuggestedWindow.Start.Value.AddSeconds(difference.TotalSeconds * randomSlot);
        _logger.LogInformation($"Current time: {now}, scheduled renewal time: {scheduledRenewalTime}");
        // Add one day to account for slots scheduled in the next 24 hours
        return scheduledRenewalTime < now.AddDays(1);
    }

    public async Task<(CertificateChain cert, IKey certKey)> OrderCertificate(string[] domains, string? oldCertId = null)
    {
        var order = await _acme.NewOrder(domains, null, null, oldCertId, "tlsserver");
        var auths = await order.Authorizations();
        var httpChallenges = await Task.WhenAll(auths.Select(a => a.Http()));
        try
        {
            await Task.WhenAll(httpChallenges.Select((a) => SaveHttpChallenge(domains, a)));
            
            var certKey = KeyFactory.NewKey(KeyAlgorithm.RS256);
            var cert = await order.Generate(new CsrInfo(), certKey);
            return (cert, certKey);
        }
        finally
        {
            foreach (var challengeContext in httpChallenges)
            {
                CleanupHttpChallenges(challengeContext);
            }
        }

    }

    private async Task SaveHttpChallenge(string[] hosts, IChallengeContext challenge)
    {
        if (challenge.Type != ChallengeTypes.Http01)
        {
            throw new Exception($"Unsupported challenge type: {challenge.Type}");
        }

        await _table.PutItemAsync(Document.FromAttributeMap(new Dictionary<string, AttributeValue> {
            { "token", new AttributeValue(challenge.Token) },
            { "response", new AttributeValue(challenge.KeyAuthz) }
        }));
        

        var attempts = 0;
        var resolved = false; 
        while (attempts < 5)
        {
            await Task.Delay(1000);
            attempts++;
            try
            {
                var allHappy = true;
                foreach (var host in hosts)
                {
                    var res = await Client.GetAsync($"http://{host}/.well-known/acme-challenge/{challenge.Token}");
                    var body = await res.Content.ReadAsStringAsync();
                    if (!body.Equals(challenge.KeyAuthz))
                    {
                        _logger.LogInformation($"Expected {challenge.KeyAuthz} but got {body} for {host}");
                        allHappy = false;
                    }
                }
                resolved = allHappy;
                break;
            }
            catch (Exception ex)
            {
                _logger.LogInformation($"Failed to resolve challenge for {string.Join(", ", hosts)}: {ex.Message}");
                if (attempts >= 5)
                {
                    throw;
                }
            }
        }

        if (!resolved)
        {
            throw new Exception($"Endpoint not serving challenge");
        }
        
        await challenge.Validate();
    }

    private async void CleanupHttpChallenges(IChallengeContext challenge)
    {
        try
        {
            await _table.DeleteItemAsync(challenge.Token);
        }
        catch (Exception)
        {
            // If we failed to delete it, presumably it didn't exist
        }
    }
    

}