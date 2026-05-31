using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using OpenIddict.EntityFrameworkCore;
using WebServiceDD.Models; // 添加此 using 以引入 UseOpenIddict 扩展方法

namespace WebServiceDD
{
    public class DBUser : IdentityDbContext<Appuser, AppRole, string>
    {
        public DBUser(DbContextOptions<DBUser> options) : base(options)
        {
        }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            // 配置 OpenIddict 的 EF Core 模型（Applications/Authorizations/Scopes/Tokens 表）
            modelBuilder.UseOpenIddict();
        }
    }
}
