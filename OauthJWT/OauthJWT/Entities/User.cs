﻿using System.ComponentModel.DataAnnotations;

namespace OauthJWT.Entities
{
    public class User
    {
        [Key]
        public int UserId { get; set; }
        public string UserName { get; set; }
        public string Password { get; set; }
        public List<UserRefreshToken> UserRefreshTokens { get; set; }
    }
}
