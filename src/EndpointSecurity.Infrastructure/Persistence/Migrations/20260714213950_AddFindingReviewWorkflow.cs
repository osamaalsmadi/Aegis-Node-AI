using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace EndpointSecurity.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddFindingReviewWorkflow : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "FindingReviews",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    FindingId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    DeviceId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Fingerprint = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false),
                    Status = table.Column<string>(type: "nvarchar(30)", maxLength: 30, nullable: false),
                    AnalystNote = table.Column<string>(type: "nvarchar(1000)", maxLength: 1000, nullable: true),
                    AnalystName = table.Column<string>(type: "nvarchar(100)", maxLength: 100, nullable: false),
                    ReviewedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_FindingReviews", x => x.Id);
                    table.ForeignKey(
                        name: "FK_FindingReviews_SecurityFindings_FindingId",
                        column: x => x.FindingId,
                        principalTable: "SecurityFindings",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_FindingReviews_DeviceId_Fingerprint_ReviewedAtUtc",
                table: "FindingReviews",
                columns: new[] { "DeviceId", "Fingerprint", "ReviewedAtUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_FindingReviews_FindingId",
                table: "FindingReviews",
                column: "FindingId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "FindingReviews");
        }
    }
}
