using EndpointSecurity.Agent;
using EndpointSecurity.Agent.Services;

var builder = Host.CreateApplicationBuilder(args);

var apiBaseUrl = builder.Configuration["Agent:ApiBaseUrl"]
    ?? throw new InvalidOperationException(
        "Agent API base URL was not configured.");

if (!Uri.TryCreate(
        apiBaseUrl,
        UriKind.Absolute,
        out var apiBaseUri))
{
    throw new InvalidOperationException(
        "Agent API base URL is invalid.");
}

builder.Services.AddSingleton(
    new HttpClient
    {
        BaseAddress = apiBaseUri,
        Timeout = TimeSpan.FromSeconds(30)
    });

builder.Services.AddSingleton<DeviceIdentityProvider>();
builder.Services.AddSingleton<WindowsSecurityCollector>();
builder.Services.AddHostedService<Worker>();

var host = builder.Build();
host.Run();
