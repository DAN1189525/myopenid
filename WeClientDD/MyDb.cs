using Microsoft.EntityFrameworkCore;

namespace WeClientDD
{
    public class MyDb : DbContext
    {
        public MyDb(DbContextOptions options) : base(options)
        {
        }

       
    }
}
