
public class SampleRequirement : AuthorizationHandler<SampleRequirement>, IAuthorizationRequirement
{
    public readonly static string PolicyName = "SamplePolicy";
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, SampleRequirement requirement)
    {
        if (!context.User.HasClaim(c => c.Type == ClaimTypes.Role))
        {
            return Task.CompletedTask;
        }

        context.Succeed(requirement);

        return Task.CompletedTask;
    }
}