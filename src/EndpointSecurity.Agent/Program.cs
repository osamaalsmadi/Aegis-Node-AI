using EndpointSecurity.Agent;
using EndpointSecurity.Agent.Services;

var builder = Host.CreateApplicationBuilder(args);

builder.Services.AddWindowsService(options =>
{
    options.ServiceName = "Endpoint Security Agent";
});

var apiBaseUrl =
    builder.Configuration["Agent:ApiBaseUrl"]
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

builder.Services.AddSingleton<
    DeviceIdentityProvider>();

builder.Services.AddSingleton<
    WindowsSecurityCollector>();

builder.Services.AddSingleton<
    EndpointTelemetryCollector>();

builder.Services.AddSingleton<
    WindowsEventCollector>();

builder.Services.AddSingleton<
    DefenderMalwareScanner>();

builder.Services.AddSingleton<
    DefenderMaintenanceService>();

builder.Services.AddHostedService<Worker>();

builder.Services.AddHostedService<
    AgentCommandWorker>();

var host = builder.Build();
host.Run();
