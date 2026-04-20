using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Widiny.Stock.Web.Models.Entities;

[Table("Account.AdminRecoveryCode")]
public class AdminRecoveryCodeEntity : AuditableEntity
{
    [Key]
    public int Id { get; set; }

    [Required]
    public int AdminId { get; set; }

    [Required]
    [MaxLength(256)]
    public string CodeHash { get; set; } = string.Empty;

    [Required]
    [MaxLength(128)]
    public string CodeSalt { get; set; } = string.Empty;

    public DateTime? UsedDateUtc { get; set; }

    [ForeignKey(nameof(AdminId))]
    public AdminEntity Admin { get; set; } = null!;
}
