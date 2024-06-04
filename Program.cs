using DotNetAuth.Data;
using DotNetAuth.Helpers;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddDbContext<ApplicationDbContext>(
    options => options.UseInMemoryDatabase("AppDb"));

builder.Services.AddControllers();

// ===== Add Identity ========
builder.Services.AddIdentity<IdentityUser, IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

// configure strongly typed settings object
builder.Services.Configure<AppSettings>(builder.Configuration.GetSection("JWT"));

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = "Bearer";
    options.DefaultChallengeScheme = "Bearer";
}).AddJwtBearer("Bearer", options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = false,
        ValidateAudience = false,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["JWT:SecretKey"]))
    };
});

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("LoginWithPasswordPolicy", policy =>
    {
        policy.Requirements.Add(new JwtPurposeRequirement("LoginWithPassword"));
    });
    options.AddPolicy("ConfirmEmailPolicy", policy =>
    {
        policy.Requirements.Add(new JwtPurposeRequirement("ConfirmEmail"));
    });
    options.AddPolicy("CreatePasswordPolicy", policy =>
    {
        policy.Requirements.Add(new JwtPurposeRequirement("CreatePassword"));
    });
    options.AddPolicy("CapturePhoneNumberPolicy", policy =>
    {
        policy.Requirements.Add(new JwtPurposeRequirement("CapturePhoneNumber"));
    });
    options.AddPolicy("ConfirmSmsPolicy", policy =>
    {
        policy.Requirements.Add(new JwtPurposeRequirement("ConfirmSms"));
    });
    options.AddPolicy("AccessUserDataPolicy", policy =>
    {
        policy.Requirements.Add(new JwtPurposeRequirement("AccessUserData"));
    });
});

builder.Services.AddSingleton<IAuthorizationHandler, JwtPurposeAuthorizationHandler>();

// Add the IConfiguration service
builder.Services.AddSingleton<IConfiguration>(builder.Configuration);

// Add OTP display on console
builder.Services.AddTransient<IEmailSender<IdentityUser>>(sp =>
{
    return new ConsoleOtpEmailSender();
});

// Add the following services
builder.Services.AddHttpContextAccessor();
builder.Services.AddDistributedMemoryCache(); // Or use a different cache provider, such as Redis

builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(10);
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
});

// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "My API",
        Version = "v1"
    });
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        In = ParameterLocation.Header,
        Description = "Please insert JWT with Bearer into field",
        Name = "Authorization",
        Type = SecuritySchemeType.ApiKey
    });
    c.AddSecurityRequirement(new OpenApiSecurityRequirement {
   {
     new OpenApiSecurityScheme
     {
       Reference = new OpenApiReference
       {
         Type = ReferenceType.SecurityScheme,
         Id = "Bearer"
       }
      },
      new string[] { }
    }
  });
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.UseSession();

app.MapControllers();

app.Run();