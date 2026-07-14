using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace EndpointSecurity.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class InitialCreate : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "ManagedDevices",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    HostName = table.Column<string>(type: "nvarchar(255)", maxLength: 255, nullable: false),
                    OperatingSystem = table.Column<string>(type: "nvarchar(100)", maxLength: 100, nullable: false),
                    OperatingSystemVersion = table.Column<string>(type: "nvarchar(100)", maxLength: 100, nullable: false),
                    Architecture = table.Column<string>(type: "nvarchar(30)", maxLength: 30, nullable: false),
                    AgentVersion = table.Column<string>(type: "nvarchar(30)", maxLength: 30, nullable: false),
                    Status = table.Column<string>(type: "nvarchar(20)", maxLength: 20, nullable: false),
                    RiskScore = table.Column<int>(type: "int", nullable: false),
                    FirstSeenUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    LastSeenUtc = table.Column<DateTime>(type: "datetime2", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ManagedDevices", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_ManagedDevices_HostName",
                table: "ManagedDevices",
                column: "HostName");

            migrationBuilder.CreateIndex(
                name: "IX_ManagedDevices_LastSeenUtc",
                table: "ManagedDevices",
                column: "LastSeenUtc");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "ManagedDevices");
        }
    }
}
