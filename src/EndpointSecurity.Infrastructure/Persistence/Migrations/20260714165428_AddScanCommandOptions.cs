using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace EndpointSecurity.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddScanCommandOptions : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "TargetPath",
                table: "AgentCommands",
                type: "nvarchar(1024)",
                maxLength: 1024,
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "TargetPath",
                table: "AgentCommands");
        }
    }
}
