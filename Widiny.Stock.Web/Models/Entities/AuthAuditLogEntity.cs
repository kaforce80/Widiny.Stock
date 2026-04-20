using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Widiny.Stock.Web.Models.Entities;

[Table("Account.AuthAuditLog")]
public class AuthAuditLogEntity : AuditableEntity
{
    [Key]
    public long Id { get; set; }

    [MaxLength(256)]
    public string? LoginId { get; set; }

    [Required]
    [MaxLength(100)]
    public string EventType { get; set; } = string.Empty;

    [Required]
    public bool IsSuccess { get; set; }

    [MaxLength(500)]
    public string? Detail { get; set; }

    [MaxLength(64)]
    public string? IpAddress { get; set; }
}
