namespace Widiny.Stock.Web.Models.Entities;

public abstract class AuditableEntity
{
    public DateTime CreateDate { get; set; } = DateTime.UtcNow;

    public DateTime ModifyDate { get; set; } = DateTime.UtcNow;
}
