namespace Auth.Core.Contracts;

public sealed record AdminStatsResponse(
    StatsSection Users,
    StatsSection Jobs,
    StatsSection Applications);

public sealed record StatsSection(
    string Status,
    int? Total,
    int? Active = null,
    int? Inactive = null,
    IReadOnlyDictionary<string, int>? ByRole = null,
    int? Pending = null,
    int? Accepted = null,
    int? Rejected = null,
    int? Closed = null,
    int? NewThisMonth = null);

public sealed record JobStats(
    int Total,
    int Pending,
    int Active,
    int Closed,
    int Rejected,
    int NewThisMonth);

public sealed record ApplicationStats(
    int Total,
    int Pending,
    int Accepted,
    int Rejected,
    int NewThisMonth);
