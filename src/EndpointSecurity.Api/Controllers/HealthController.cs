using System.Diagnostics;
using EndpointSecurity.Infrastructure.Persistence;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace EndpointSecurity.Api.Controllers;

[ApiController]
[Route("api/[controller]")]
public sealed class HealthController(
    EndpointSecurityDbContext dbContext,
    IHttpClientFactory httpClientFactory,
    ILogger<HealthController> logger)
    : ControllerBase
{
    [HttpGet]
    public async Task<IActionResult> Get(
        CancellationToken cancellationToken)
    {
        var databaseTimer = Stopwatch.StartNew();
        var databaseAvailable = false;

        try
        {
            databaseAvailable =
                await dbContext.Database.CanConnectAsync(
                    cancellationToken);
        }
        catch (Exception exception)
        {
            logger.LogWarning(
                "Database health check failed. " +
                "ExceptionType={ExceptionType}",
                exception.GetType().Name);
        }

        databaseTimer.Stop();

        var aiTimer = Stopwatch.StartNew();
        var aiAvailable = false;

        try
        {
            using var timeout =
                CancellationTokenSource.CreateLinkedTokenSource(
                    cancellationToken);

            timeout.CancelAfter(
                TimeSpan.FromSeconds(2));

            var client =
                httpClientFactory.CreateClient("Ollama");

            using var response = await client.GetAsync(
                "/api/tags",
                timeout.Token);

            aiAvailable = response.IsSuccessStatusCode;
        }
        catch (Exception exception)
        {
            logger.LogWarning(
                "Local AI health check failed. " +
                "ExceptionType={ExceptionType}",
                exception.GetType().Name);
        }

        aiTimer.Stop();

        var status = !databaseAvailable
            ? "Unhealthy"
            : aiAvailable
                ? "Healthy"
                : "Degraded";

        var result = new
        {
            service = "EndpointSecurity.Api",
            status,
            version = "1.0.0",
            ready = databaseAvailable,
            utcTime = DateTime.UtcNow,
            dependencies = new
            {
                database = new
                {
                    available = databaseAvailable,
                    required = true,
                    responseTimeMs =
                        databaseTimer.ElapsedMilliseconds
                },
                localAi = new
                {
                    available = aiAvailable,
                    required = false,
                    provider = "Ollama",
                    model = "qwen2.5:1.5b",
                    local = true,
                    responseTimeMs =
                        aiTimer.ElapsedMilliseconds
                }
            }
        };

        if (!databaseAvailable)
        {
            return StatusCode(
                StatusCodes.Status503ServiceUnavailable,
                result);
        }

        return Ok(result);
    }

    [HttpGet("live")]
    public IActionResult GetLiveness()
    {
        return Ok(new
        {
            service = "EndpointSecurity.Api",
            status = "Healthy",
            version = "1.0.0",
            utcTime = DateTime.UtcNow
        });
    }
}
