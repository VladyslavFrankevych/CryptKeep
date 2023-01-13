import base64
import random
import string
import time
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from sqlalchemy import create_engine, Column, Integer, String, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.ext.mutable import MutableDict
from sqlalchemy.orm import sessionmaker
import telebot
from config import TOKEN, URL

Base = declarative_base()

class Password(Base):
    __tablename__ = 'passwords'
    user_id = Column(Integer, primary_key=True)
    master_password_hash = Column(String)
    passwords = Column(MutableDict.as_mutable(JSON))

engine = create_engine(URL)
Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)
session = Session()

bot = telebot.TeleBot(TOKEN)

@bot.callback_query_handler(func=lambda call: True)
def callback_handler(call):
    if call.data == 'close':
        bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.id, text='Closed.')

@bot.message_handler(commands=['start'])
def start(message):
    bot.send_message(message.chat.id, "Welcome to the password manager bot! Enter your master password:")
    bot.register_next_step_handler(message, master_password)

def master_password(message):
    master_password = message.text
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256,
        length=32,
        salt=b'salt_',
        iterations=100000,
        backend=default_backend()
    )
    key = str(base64.urlsafe_b64encode(kdf.derive(master_password.encode())))
    password_record = session.query(Password).filter(Password.user_id == message.chat.id).one_or_none()
    if password_record:
        if password_record.master_password_hash == key:
            bot.send_message(message.chat.id, 'Enter your new master password:')
            bot.register_next_step_handler(message, process_new_master_password)
        else:
            bot.send_message(message.chat.id, "Incorrect master password.")
    else:
        password_record = Password(user_id=message.chat.id, master_password_hash=key, passwords={})
        session.add(password_record)
        session.commit()
        bot.send_message(message.chat.id, "Master password created successfully.")
        time.sleep(1)
        bot.delete_message(chat_id=message.chat.id, message_id=message.message_id)

def process_new_master_password(message):
    master_password = message.text
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256,
        length=32,
        salt=b'salt_',
        iterations=100000,
        backend=default_backend()
    )
    key = str(base64.urlsafe_b64encode(kdf.derive(master_password.encode())))
    password_record = session.query(Password).filter(Password.user_id == message.chat.id).one()
    password_record.master_password_hash = key
    session.commit()
    bot.send_message(message.chat.id, "Master password changed successfully.")
    time.sleep(1)
    bot.delete_message(chat_id=message.chat.id, message_id=message.message_id)

@bot.message_handler(commands=['passwords'])
def passwords(message):
    bot.send_message(message.chat.id, 'Enter your master password:')
    bot.register_next_step_handler(message, process_passwords)

def process_passwords(message):
    master_password = message.text
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256,
        length=32,
        salt=b'salt_',
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    password_record = session.query(Password).filter(Password.user_id == message.chat.id).one()
    if password_record.master_password_hash == str(key):
        bot.delete_message(chat_id=message.chat.id, message_id=message.message_id)
        cipher = Fernet(key)
        decrypted_passwords = ''
        for k, v in password_record.passwords.items():
            markup = telebot.types.InlineKeyboardMarkup()
            close_button = telebot.types.InlineKeyboardButton('Close', callback_data='close')
            markup.add(close_button)
            decrypted_passwords+=f'{k}: `{cipher.decrypt(base64.b64decode(v)).decode()}`\n'
        if decrypted_passwords:
            bot.send_message(message.chat.id, decrypted_passwords, parse_mode='Markdown', reply_markup=markup)
        else:
            bot.send_message(message.chat.id, "You don't have any password records.")
    else:
        bot.send_message(message.chat.id, "Incorrect master password.")

@bot.message_handler(commands=['generate'])
def gen(message):
    generated_password = ''.join(random.choices(string.ascii_uppercase + string.ascii_lowercase + string.digits + string.ascii_uppercase + string.ascii_lowercase + string.digits + string.punctuation, k=12)).replace("'", "")
    bot.send_message(message.chat.id, f'Your password is `{generated_password}`', parse_mode='Markdown')

@bot.message_handler(commands=['delete'])
def delete(message):
    bot.send_message(message.chat.id, 'Enter a keyword of password you want to delete:')
    bot.register_next_step_handler(message, process_delete)

def process_delete(message):
    password_record = session.query(Password).filter(Password.user_id == message.chat.id).one()
    if message.text in password_record.passwords.keys():
        del password_record.passwords[message.text]
        session.commit()
        bot.send_message(message.chat.id, text='Password deleted successfully.')
    else:
        bot.send_message(message.chat.id, text='There is no password with that keyword.')

@bot.message_handler(commands=['new'])
def new(message):
    bot.send_message(message.chat.id, 'Enter your master password:')
    bot.register_next_step_handler(message, process_master_password)

def process_master_password(message):
    master_password = message.text
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256,
        length=32,
        salt=b'salt_',
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    password_record = session.query(Password).filter(Password.user_id == message.chat.id).one()
    if password_record.master_password_hash == str(key):
        bot.delete_message(chat_id=message.chat.id, message_id=message.message_id)
        bot.send_message(message.chat.id, 'Enter a keyword:')
        bot.register_next_step_handler(message, process_keyword, key)
    else:
        bot.send_message(message.chat.id, "Incorrect master password.")

def process_keyword(message, key):
    keyword = message.text
    bot.send_message(message.chat.id, 'Enter a password:')
    bot.register_next_step_handler(message, process_new_password, key, keyword)

def process_new_password(message, key, keyword):
    password = message.text
    cipher = Fernet(key)
    encrypted_password = cipher.encrypt(password.encode())
    encoded_password = base64.b64encode(encrypted_password).decode()
    password_record = session.query(Password).filter(Password.user_id == message.chat.id).one()
    password_record.passwords[keyword] = encoded_password
    session.commit()
    bot.send_message(message.chat.id, "Password created successfully.")
    time.sleep(1)
    bot.delete_message(chat_id=message.chat.id, message_id=message.message_id)

if __name__ == "__main__":
    bot.polling()