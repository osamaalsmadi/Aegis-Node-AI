using EndpointSecurity.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace EndpointSecurity.Infrastructure.Persistence;

public sealed class EndpointSecurityDbContext(
    DbContextOptions<EndpointSecurityDbContext> options)
    : DbContext(options)
{
    public DbSet<ManagedDevice> ManagedDevices =>
        Set<ManagedDevice>();

    public DbSet<SecurityPostureSnapshot> SecurityPostureSnapshots =>
        Set<SecurityPostureSnapshot>();

    public DbSet<EndpointTelemetryScan> EndpointTelemetryScans =>
        Set<EndpointTelemetryScan>();

    public DbSet<SecurityFinding> SecurityFindings =>
        Set<SecurityFinding>();

    public DbSet<NetworkConnectionSnapshot> NetworkConnectionSnapshots =>
        Set<NetworkConnectionSnapshot>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        var device = modelBuilder.Entity<ManagedDevice>();

        device.ToTable("ManagedDevices");
        device.HasKey(x => x.Id);

        device.Property(x => x.HostName)
            .HasMaxLength(255)
            .IsRequired();

        device.Property(x => x.OperatingSystem)
            .HasMaxLength(100)
            .IsRequired();

        device.Property(x => x.OperatingSystemVersion)
            .HasMaxLength(100)
            .IsRequired();

        device.Property(x => x.Architecture)
            .HasMaxLength(30)
            .IsRequired();

        device.Property(x => x.AgentVersion)
            .HasMaxLength(30)
            .IsRequired();

        device.Property(x => x.Status)
            .HasConversion<string>()
            .HasMaxLength(20)
            .IsRequired();

        device.HasIndex(x => x.HostName);
        device.HasIndex(x => x.LastSeenUtc);

        var posture =
            modelBuilder.Entity<SecurityPostureSnapshot>();

        posture.ToTable("SecurityPostureSnapshots");
        posture.HasKey(x => x.Id);

        posture.HasOne<ManagedDevice>()
            .WithMany()
            .HasForeignKey(x => x.DeviceId)
            .OnDelete(DeleteBehavior.Cascade);

        posture.HasIndex(x => new
        {
            x.DeviceId,
            x.CollectedAtUtc
        });

        var scan =
            modelBuilder.Entity<EndpointTelemetryScan>();

        scan.ToTable("EndpointTelemetryScans");
        scan.HasKey(x => x.Id);

        scan.HasOne<ManagedDevice>()
            .WithMany()
            .HasForeignKey(x => x.DeviceId)
            .OnDelete(DeleteBehavior.Cascade);

        scan.HasIndex(x => new
        {
            x.DeviceId,
            x.CollectedAtUtc
        });

        var finding =
            modelBuilder.Entity<SecurityFinding>();

        finding.ToTable("SecurityFindings");
        finding.HasKey(x => x.Id);

        finding.Property(x => x.Category)
            .HasConversion<string>()
            .HasMaxLength(50)
            .IsRequired();

        finding.Property(x => x.Severity)
            .HasConversion<string>()
            .HasMaxLength(20)
            .IsRequired();

        finding.Property(x => x.Title)
            .HasMaxLength(200)
            .IsRequired();

        finding.Property(x => x.Description)
            .HasMaxLength(2000)
            .IsRequired();

        finding.Property(x => x.ProcessName)
            .HasMaxLength(255);

        finding.Property(x => x.FilePath)
            .HasMaxLength(1024);

        finding.Property(x => x.CommandLine)
            .HasMaxLength(4000);

        finding.HasOne<EndpointTelemetryScan>()
            .WithMany()
            .HasForeignKey(x => x.ScanId)
            .OnDelete(DeleteBehavior.Cascade);

        finding.HasIndex(x => x.DeviceId);
        finding.HasIndex(x => x.Severity);

        var connection =
            modelBuilder.Entity<NetworkConnectionSnapshot>();

        connection.ToTable("NetworkConnectionSnapshots");
        connection.HasKey(x => x.Id);

        connection.Property(x => x.Protocol)
            .HasMaxLength(10)
            .IsRequired();

        connection.Property(x => x.LocalAddress)
            .HasMaxLength(64)
            .IsRequired();

        connection.Property(x => x.RemoteAddress)
            .HasMaxLength(64)
            .IsRequired();

        connection.Property(x => x.State)
            .HasMaxLength(30)
            .IsRequired();

        connection.Property(x => x.ProcessName)
            .HasMaxLength(255);

        connection.HasOne<EndpointTelemetryScan>()
            .WithMany()
            .HasForeignKey(x => x.ScanId)
            .OnDelete(DeleteBehavior.Cascade);

        connection.HasIndex(x => x.DeviceId);
        connection.HasIndex(x => x.RemoteAddress);
        connection.HasIndex(x => x.RemotePort);

        var agentCommand =
            modelBuilder.Entity<
                EndpointSecurity.Domain.Entities.AgentCommand>();

        agentCommand.ToTable("AgentCommands");
        agentCommand.HasKey(x => x.Id);

        agentCommand.Property(x => x.Type)
            .HasConversion<string>()
            .HasMaxLength(50)
            .IsRequired();

        agentCommand.Property(x => x.Status)
            .HasConversion<string>()
            .HasMaxLength(30)
            .IsRequired();

        agentCommand.Property(x => x.ResultMessage)
            .HasMaxLength(1000);

        agentCommand.Property(x => x.ErrorMessage)
            .HasMaxLength(2000);

        agentCommand.HasIndex(
            x => new
            {
                x.DeviceId,
                x.Status
            });

        agentCommand.HasIndex(x => x.RequestedAtUtc);
    }
}

