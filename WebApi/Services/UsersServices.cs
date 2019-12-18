using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using WebApi.Models;

namespace WebApi.Services
{
    public interface IUserService
    {
        User Authorization(string username, string password);
        User GetById(int id);
        IEnumerable<User> GetAll();
        User Create(User user, string password);
    }
    public class UsersServices: IUserService
    {
        private DataContext _ctx;
        public UsersServices(DataContext ctx)
        {
            _ctx = ctx;
        }

        public User Authorization(string username, string password)
        {
            if (string.IsNullOrEmpty(username))
                throw new AppException("Введите логин!");
            if (string.IsNullOrEmpty(password))
                throw new AppException("Введите пароль!");
            //if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
            //    return null;

            // ищем пользователя
            var user = _ctx.Users.SingleOrDefault(x => x.Username == username);

            // если пользователь не существует (т.е. не был создан)
            if (user == null)
                throw new AppException("Пользователь не найден.");
            //return null;

            // check if password is correct
            if (!VerifyPasswordHash(password, user.PasswordHash, user.PasswordSalt))
                return null;

            // authentication successful
            return user;
        }

        public User GetById(int id)
        {
            return _ctx.Users.Find(id);
        }

        public IEnumerable<User> GetAll()
        {
            return _ctx.Users;
        }
        public User Create(User user, string password)
        {
            // валидация
            if (string.IsNullOrWhiteSpace(user.FirstName))
                throw new AppException("Введите имя!");
            if (string.IsNullOrWhiteSpace(user.LastName))
                throw new AppException("Введите фамилию!");
            if (string.IsNullOrWhiteSpace(user.Username))
                throw new AppException("Введите логин!");
            if (string.IsNullOrWhiteSpace(password))
                throw new AppException("Введите пароль!");
            if (_ctx.Users.Any(x => x.Username == user.Username))
                throw new AppException("Логин " + user.Username + " уже существует.");

            byte[] passwordHash, passwordSalt;
            CreatePasswordHash(password, out passwordHash, out passwordSalt);

            user.PasswordHash = passwordHash;
            user.PasswordSalt = passwordSalt;

            _ctx.Users.Add(user);
            _ctx.SaveChanges();

            return user;
        }

        private static void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
        {
            if (password == null) throw new ArgumentNullException("Введите пароль!");
            //if (string.IsNullOrWhiteSpace(password)) throw new ArgumentException("Value cannot be empty or whitespace only string.", "password");

            using (var hmac = new System.Security.Cryptography.HMACSHA512())
            {
                passwordSalt = hmac.Key;
                passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            }
        }

        private static bool VerifyPasswordHash(string password, byte[] storedHash, byte[] storedSalt)
        {
            if (password == null) throw new ArgumentNullException("пароль");
            if (string.IsNullOrWhiteSpace(password)) throw new ArgumentException("Значение не может быть пустым.", "password");
            if (storedHash.Length != 64) throw new ArgumentException("Недопустимая длина hash пароля (ожидается 64 байта).", "passwordHash");
            if (storedSalt.Length != 128) throw new ArgumentException("Неверная длина salt пароля (ожидается 128 байт).", "passwordSalt");

            using (var hmac = new System.Security.Cryptography.HMACSHA512(storedSalt))
            {
                var computedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
                for (int i = 0; i < computedHash.Length; i++)
                {
                    if (computedHash[i] != storedHash[i]) return false;
                }
            }

            return true;
        }
    }
}
