using Widiny.Stock.Web.Models.Entities;
using Microsoft.EntityFrameworkCore;

namespace Widiny.Stock.Web.Data;

public class StockDbContext(DbContextOptions<StockDbContext> options) : DbContext(options)
{
    public DbSet<AdminEntity> Admins => Set<AdminEntity>();
    public DbSet<AdminRecoveryCodeEntity> AdminRecoveryCodes => Set<AdminRecoveryCodeEntity>();
    public DbSet<AuthAuditLogEntity> AuthAuditLogs => Set<AuthAuditLogEntity>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.Entity<AdminEntity>()
            .HasIndex(x => x.LoginId)
            .IsUnique();

        modelBuilder.Entity<AdminRecoveryCodeEntity>()
            .HasOne(x => x.Admin)
            .WithMany()
            .HasForeignKey(x => x.AdminId)
            .OnDelete(DeleteBehavior.Cascade);

        modelBuilder.Entity<AdminRecoveryCodeEntity>()
            .HasIndex(x => new { x.AdminId, x.UsedDateUtc });

        SetAuditDefaults<AdminEntity>(modelBuilder);
        SetAuditDefaults<AdminRecoveryCodeEntity>(modelBuilder);
        SetAuditDefaults<AuthAuditLogEntity>(modelBuilder);
    }

    private static void SetAuditDefaults<T>(ModelBuilder modelBuilder) where T : AuditableEntity
    {
        modelBuilder.Entity<T>()
            .Property(x => x.CreateDate)
            .HasDefaultValueSql("CURRENT_TIMESTAMP");

        modelBuilder.Entity<T>()
            .Property(x => x.ModifyDate)
            .HasDefaultValueSql("CURRENT_TIMESTAMP");
    }
}
