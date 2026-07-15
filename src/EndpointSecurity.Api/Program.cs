using System.Text;
using System.Text.Json.Serialization;
using EndpointSecurity.Application.Devices;
using EndpointSecurity.Application.Findings;
using EndpointSecurity.Application.SecurityEvents;
using EndpointSecurity.Application.SecurityPosture;
using EndpointSecurity.Application.Telemetry;
using EndpointSecurity.Infrastructure.Persistence;
using EndpointSecurity.Infrastructure.Services;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

if (string.IsNullOrWhiteSpace(
        builder.Configuration["urls"]))
{
    builder.WebHost.UseUrls(
        "http://127.0.0.1:5235");
}

builder.Services
    .AddControllers()
    .AddJsonOptions(options =>
    {
        options.JsonSerializerOptions.Converters.Add(
            new JsonStringEnumConverter());
    });

builder.Services.AddAuthorization();
builder.Services.AddOpenApi();

var ollamaBaseUrl =
    builder.Configuration["Ollama:BaseUrl"]
    ?? "http://127.0.0.1:11434";

if (!Uri.TryCreate(
        ollamaBaseUrl,
        UriKind.Absolute,
        out var ollamaBaseAddress) ||
    !ollamaBaseAddress.IsLoopback ||
    ollamaBaseAddress.Scheme is not ("http" or "https"))
{
    throw new InvalidOperationException(
        "Ollama must use a valid local loopback address.");
}

builder.Services.AddHttpClient(
    "Ollama",
    client =>
    {
        client.BaseAddress = ollamaBaseAddress;
        client.Timeout = Timeout.InfiniteTimeSpan;
    });

var connectionString =
    builder.Configuration.GetConnectionString(
        "EndpointSecurityDatabase")
    ?? throw new InvalidOperationException(
        "EndpointSecurityDatabase connection string was not found.");

builder.Services.AddDbContext<
    EndpointSecurityDbContext>(options =>
        options.UseSqlServer(connectionString));

builder.Services.AddScoped<IDeviceService, DeviceService>();
builder.Services.AddScoped<ISecurityPostureService, SecurityPostureService>();
builder.Services.AddScoped<IEndpointTelemetryService, EndpointTelemetryService>();
builder.Services.AddScoped<IFindingManagementService, FindingManagementService>();
builder.Services.AddScoped<IWindowsSecurityEventService, WindowsSecurityEventService>();

var app = builder.Build();

try
{
    using var scope = app.Services.CreateScope();

    var database = scope.ServiceProvider
        .GetRequiredService<EndpointSecurityDbContext>();

    database.Database.Migrate();
}
catch (Exception exception)
{
    WriteSafeLog(
        "Error",
        "DatabaseMigration",
        "startup",
        exception);

    throw;
}

app.UseExceptionHandler(errorApplication =>
{
    errorApplication.Run(async context =>
    {
        var exception = context.Features
            .Get<IExceptionHandlerFeature>()?
            .Error;

        var exceptionType =
            exception?.GetType().FullName
            ?? "Unknown";

        var logger = context.RequestServices
            .GetRequiredService<ILoggerFactory>()
            .CreateLogger("SafeApiException");

        logger.LogError(
            "Unhandled API failure. TraceId={TraceId}; " +
            "ExceptionType={ExceptionType}",
            context.TraceIdentifier,
            exceptionType);

        WriteSafeLog(
            "Error",
            "UnhandledApiRequest",
            context.TraceIdentifier,
            exception);

        context.Response.StatusCode =
            StatusCodes.Status500InternalServerError;

        context.Response.ContentType =
            "application/problem+json";

        await context.Response.WriteAsJsonAsync(
            new
            {
                type = "https://httpstatuses.com/500",
                title = "An unexpected API error occurred.",
                status = 500,
                traceId = context.TraceIdentifier
            });
    });
});

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseDefaultFiles();
app.UseStaticFiles();
app.UseAuthorization();

app.MapControllers();

app.MapFallback(
    "/api/{**path}",
    async context =>
    {
        context.Response.StatusCode =
            StatusCodes.Status404NotFound;

        context.Response.ContentType =
            "application/problem+json";

        await context.Response.WriteAsJsonAsync(
            new
            {
                type = "https://httpstatuses.com/404",
                title = "The requested API endpoint was not found.",
                status = 404,
                traceId = context.TraceIdentifier
            });
    });

app.MapFallbackToFile("index.html");

WriteSafeLog(
    "Information",
    "ApiStartup",
    "startup",
    null);

app.Run();

static void WriteSafeLog(
    string level,
    string category,
    string? traceId,
    Exception? exception)
{
    try
    {
        var logDirectory = Path.Combine(
            Environment.GetFolderPath(
                Environment.SpecialFolder.CommonApplicationData),
            "EndpointSecurityPlatform",
            "Logs",
            "Api");

        Directory.CreateDirectory(logDirectory);

        var logPath = Path.Combine(
            logDirectory,
            "api.log");

        var safeTraceId =
            string.IsNullOrWhiteSpace(traceId)
                ? "-"
                : traceId
                    .Replace('\t', '_')
                    .Replace('\r', '_')
                    .Replace('\n', '_');

        var exceptionType =
            exception?.GetType().FullName
            ?? "-";

        var line =
            $"{DateTime.UtcNow:O}\t{level}\t{category}\t" +
            $"TraceId={safeTraceId}\tException={exceptionType}";

        using var stream = new FileStream(
            logPath,
            FileMode.Append,
            FileAccess.Write,
            FileShare.ReadWrite);

        using var writer = new StreamWriter(
            stream,
            new UTF8Encoding(false));

        writer.WriteLine(line);
    }
    catch
    {
    }
}
