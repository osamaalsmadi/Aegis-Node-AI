using EndpointSecurity.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace EndpointSecurity.Infrastructure.Persistence;

public sealed class EndpointSecurityDbContext(
    DbContextOptions<EndpointSecurityDbContext> options)
    : DbContext(options)
{
    public DbSet<ManagedDevice> ManagedDevices =>
        Set<ManagedDevice>();

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

        device.Property(x => x.RiskScore)
            .IsRequired();

        device.HasIndex(x => x.HostName);
        device.HasIndex(x => x.LastSeenUtc);
    }
}