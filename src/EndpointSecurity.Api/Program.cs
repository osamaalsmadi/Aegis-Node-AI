using System.Text.Json.Serialization;
using EndpointSecurity.Application.Devices;
using EndpointSecurity.Application.SecurityPosture;
using EndpointSecurity.Application.Telemetry;
using EndpointSecurity.Infrastructure.Persistence;
using EndpointSecurity.Infrastructure.Services;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services
    .AddControllers()
    .AddJsonOptions(options =>
    {
        options.JsonSerializerOptions.Converters.Add(
            new JsonStringEnumConverter());
    });

builder.Services.AddOpenApi();

var connectionString = builder.Configuration.GetConnectionString(
    "EndpointSecurityDatabase")
    ?? throw new InvalidOperationException(
        "EndpointSecurityDatabase connection string was not found.");

builder.Services.AddDbContext<EndpointSecurityDbContext>(options =>
    options.UseSqlServer(connectionString));

builder.Services.AddScoped<IDeviceService, DeviceService>();

builder.Services.AddScoped<
    ISecurityPostureService,
    SecurityPostureService>();

builder.Services.AddScoped<
    IEndpointTelemetryService,
    EndpointTelemetryService>();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseDefaultFiles();
app.UseStaticFiles();

app.UseAuthorization();

app.MapControllers();

app.MapFallbackToFile("index.html");

app.Run();
