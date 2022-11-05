var builder = WebApplication.CreateBuilder(args);

builder.Services.AddSingleton<ITokenService>(new TokenService());
builder.Services.AddSingleton<IUserRepositoryService>(new UserRepositoryService());

builder.Services
    .AddAuthorization(options =>
    {
        options.AddPolicy(SampleRequirement.PolicyName, policy =>
        {
            policy.AddRequirements(new SampleRequirement());
        });

        options.AddPolicy("AdminOrMod", policy =>
        {
            policy.RequireRole("admin", "moderator");
        });

        options.AddPolicy("ABC", policy => {
            policy.RequireClaim("ABC");
        });
    });

builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(opt =>
    {
        opt.TokenValidationParameters = new()
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = builder.Configuration["Jwt:Issuer"],
            ValidAudience = builder.Configuration["Jwt:Issuer"],
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]))
        };
    });

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/", [AllowAnonymous] () => "This a demo for JWT Authentication using Minimalist Web API");

app.MapGet("/login", [AllowAnonymous] async (HttpContext http, ITokenService tokenService, IUserRepositoryService userRepositoryService) =>
{
    var userModel = await http.Request.ReadFromJsonAsync<UserModel>();

    if (userModel == null)
    {
        http.Response.StatusCode = 401;
        return;
    }

    var userDto = userRepositoryService.GetUser(userModel: userModel);

    if (userDto == null)
    {
        http.Response.StatusCode = 401;
        return;
    }

    var token = tokenService.BuildToken(builder.Configuration["Jwt:Key"], builder.Configuration["Jwt:Issuer"], userDto);
    await http.Response.WriteAsJsonAsync(new { token = token });

    return;
});

app.MapGet("/do-action", [Authorize] () => "Action Succeeded");
app.MapGet("/do-action-by-roles", [Authorize(Roles = "admin")] () => "Action Succeeded");
app.MapGet("/do-action-by-policy", [Authorize(Policy = "SamplePolicy")] () => "Action Succeeded");
app.MapGet("/do-action-by-role-group", [Authorize(Policy = "AdminOrMod")] () => "Action Succeeded");

await app.RunAsync();
