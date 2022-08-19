using Amazon.DynamoDBv2.DocumentModel;
using Amazon.DynamoDBv2.Model;
using Certes;
using Certes.Acme;
using Certes.Acme.Resource;
using Certes.Pkcs;

namespace CertManager;

public class CertificateIssuance
{
    private IAccountContext? _account;
    private readonly string _email;
    private readonly AcmeContext _acme;
    private static readonly HttpClient Client = new HttpClient();
    private readonly Table _table;

    public CertificateIssuance(string email, bool staging, IKey accountKey, Table table)
    {
        _acme = new AcmeContext(staging ? WellKnownServers.LetsEncryptStagingV2 : WellKnownServers.LetsEncryptV2, accountKey);
        _email = email;
        _table = table;
    }

    public async void Init()
    {
        _account = await _acme.NewAccount(_email, true);
    }

    public async Task<(CertificateChain cert, IKey certKey)> OrderCertificate(string[] domains)
    {
        var order = await _acme.NewOrder(domains);
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
                        allHappy = false;
                    }
                }
                resolved = allHappy;
                break;
            }
            catch (Exception)
            {
                if (attempts >= 5)
                {
                    throw;
                }
            }
        }

        if (!resolved)
        {
            throw new Exception($"Endpoint for {challenge.Location.Host} not serving challenge");
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