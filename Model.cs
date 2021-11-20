public record UserDto(string UserName, string Password);

public record UserModel([Required] string UserName, [Required] string Password);