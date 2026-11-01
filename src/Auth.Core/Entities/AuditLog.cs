using SharedKernel;

namespace Auth.Core.Entities;

public class AuditLog : Entity
{
    public Guid ActorUserId { get; private set; }
    public string Action { get; private set; } = "";
    public string TargetType { get; private set; } = "";
    public Guid TargetId { get; private set; }
    public string? Reason { get; private set; }
    public string? Metadata { get; private set; }

    private AuditLog() { }

    public AuditLog(
        Guid actorUserId,
        string action,
        string targetType,
        Guid targetId,
        string? reason = null,
        string? metadata = null)
    {
        ActorUserId = actorUserId;
        Action = action;
        TargetType = targetType;
        TargetId = targetId;
        Reason = reason;
        Metadata = metadata;
    }
}
