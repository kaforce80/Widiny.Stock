using Widiny.Stock.Web.Models.Entities;
using Microsoft.EntityFrameworkCore;

namespace Widiny.Stock.Web.Data;

public class StockDbContext(DbContextOptions<StockDbContext> options) : DbContext(options)
{
    public DbSet<AdminEntity> Admins => Set<AdminEntity>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.Entity<AdminEntity>()
            .HasIndex(x => x.LoginId)
            .IsUnique();

        modelBuilder.Entity<AdminEntity>()
            .Property(x => x.CreateDate)
            .HasDefaultValueSql("CURRENT_TIMESTAMP");

        modelBuilder.Entity<AdminEntity>()
            .Property(x => x.ModifyDate)
            .HasDefaultValueSql("CURRENT_TIMESTAMP");
    }
}
