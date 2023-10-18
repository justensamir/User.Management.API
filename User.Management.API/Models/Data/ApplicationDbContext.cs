﻿using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace User.Management.API.Models.Data
{
    public class ApplicationDbContext : IdentityDbContext<IdentityUser>
    {

        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options ) : base(options)
        {
            
        }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);
            SeedRoles(builder);
        }


        private void SeedRoles(ModelBuilder builder)
        {
            builder.Entity<IdentityRole>().HasData(
                new IdentityRole (){ Name="Admin", ConcurrencyStamp="1", NormalizedName="Admin"},
                new IdentityRole (){ Name="User", ConcurrencyStamp="2", NormalizedName= "User" },
                new IdentityRole (){ Name="HR", ConcurrencyStamp="3", NormalizedName="HR"}
                );
        }

        private void SeedUsers(ModelBuilder builder)
        {
            builder.Entity<IdentityUser>().HasData(
                new IdentityUser() 
                {
                    Email="mo.samir@arpu.com",
                    EmailConfirmed= true,
                    NormalizedEmail= "mo.samir@arpu.com"
                }
                );
        }
    }
}