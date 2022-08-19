using System.Reflection;


HttpClient Client = new HttpClient();
var res = await Client.GetAsync("http://ftc-cloud.pdx-staging.ftclive.org/.well-known/acme-challenge/tnoYHxePIU6rkA8lDqpjEziLa2VCedu6ATuEt1gfzg4");
var body = await res.Content.ReadAsStringAsync();
Console.Out.WriteLine(body);