
public interface IUserRepositoryService
{
    UserDto? GetUser(UserModel userModel);
}

public class UserRepositoryService : IUserRepositoryService
{
    private List<UserDto> _users => new()
    {
        new("Anu Viswan", "anu"),
        new("Jia Anu", "jia"),
        new("Naina Anu", "naina"),
        new("Sreena Anu", "sreena"),
    };

    public UserDto? GetUser(UserModel userModel) => _users.FirstOrDefault(x => string.Equals(x.UserName, userModel.UserName) && string.Equals(x.Password, userModel.Password));
}

public interface ITokenService
{
    string BuildToken(string key, string issuer, UserDto user);
}

public class TokenService : ITokenService
{
    private TimeSpan ExpiryDuration = new TimeSpan(0, 30, 0);
    public string BuildToken(string key, string issuer, UserDto user)
    {
        var claims = new[]
        {
            new Claim(ClaimTypes.Name, user.UserName),
            new Claim(ClaimTypes.NameIdentifier, Guid.NewGuid().ToString()),
            // new Claim(ClaimTypes.Role, "admin"),
            new Claim(ClaimTypes.Role, "guest"),
            new Claim(ClaimTypes.Role, "moderator"),
            new Claim(ClaimTypes.Role, "leader"),
        };

        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key));
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256Signature);
        var tokenDescriptor = new JwtSecurityToken(issuer, issuer, claims, expires: DateTime.Now.Add(ExpiryDuration), signingCredentials: credentials);

        return new JwtSecurityTokenHandler().WriteToken(tokenDescriptor);
    }
}


