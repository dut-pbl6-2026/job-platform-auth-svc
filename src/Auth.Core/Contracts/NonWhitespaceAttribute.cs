using System.ComponentModel.DataAnnotations;

namespace Auth.Core.Contracts;

/// <summary>
/// Rejects whitespace-only strings. <see cref="RequiredAttribute"/> allows
/// "   ", so this complements it on fields that are trimmed before use.
/// Null is valid here (leave presence checks to <c>[Required]</c>).
/// </summary>
[AttributeUsage(AttributeTargets.Property | AttributeTargets.Field | AttributeTargets.Parameter)]
public sealed class NonWhitespaceAttribute : ValidationAttribute
{
    protected override ValidationResult? IsValid(object? value, ValidationContext _)
    {
        if (value is null)
            return ValidationResult.Success;
        if (value is string s && string.IsNullOrWhiteSpace(s))
            return new ValidationResult(ErrorMessage ?? "Value cannot be blank");
        return ValidationResult.Success;
    }
}
