from flask import Blueprint, render_template, request, flash
from flask_login import login_required, current_user
from .server import tripDES, AES, RSA, SHA3, DH, empty_static
import os

views = Blueprint('views', __name__)

UPLOAD_FOLDER = "website/static/"

@views.route('/', methods=['GET', 'POST'])
@login_required
def home():
    folders = empty_static.list_folders("./" + UPLOAD_FOLDER)
    print(folders)
    for folder in folders:
        empty_static.empty_folder(folder)
    return render_template("home.html", user=current_user)

@views.route('/method' , methods = ['GET', 'POST'])
def method():
    method = request.args.get('met')
    if method == "3_des":
        return render_template('3_des.html', user=current_user)
    elif method == "3_des_dec":
        return render_template('3_des_dec.html', user=current_user)
    elif method == "aes":
        return render_template('aes.html', user=current_user)
    elif method == "aes_dec":
        return render_template('aes_dec.html', user=current_user)
    elif method == "rsa_keys":
        RSA.generate_key_pair(UPLOAD_FOLDER)
        pub_key = './static/keys/public_key.pem'
        pvt_key = './static/keys/private_key.pem'
        return render_template('download_keys.html', user=current_user, public_key=pub_key, private_key=pvt_key)
    elif method == "rsa_enc":
        return render_template('rsa_enc.html', user=current_user)
    elif method == "rsa_dec":
        return render_template('rsa_dec.html', user=current_user)
    elif method == "sha3":
        return render_template('sha3.html', user=current_user)
    elif method == "dh":
        DH.generate_keys(UPLOAD_FOLDER)
        pub_key = './static/keys/public_key.pem'
        pvt_key = './static/keys/private_key.pem'
        return render_template('download_keys.html', user=current_user, public_key=pub_key, private_key=pvt_key)
    else:
        return render_template('home.html', user=current_user)

@views.route('/process' , methods = ['GET', 'POST'])
def process():
    request_method = request.method
    if request_method == 'POST':
        method = request.form['method']
        if method == "3_des":
            file_for_enc = request.files['file_for_enc']
            name_enc_file = request.form['name_enc_file']
            key = request.form['key']
            return enc_dec(method=method, file=file_for_enc, name=name_enc_file, key=key, process="enc", key_size="")
        elif method == "3_des_dec":
            file_for_dec = request.files['file_for_dec']
            name_dec_file = request.form['name_dec_file']
            key = request.form['key']
            return enc_dec(method=method, file=file_for_dec, name=name_dec_file, key=key, process="dec", key_size="")
        elif method == "aes":
            file_for_enc = request.files['file_for_enc']
            name_enc_file = request.form['name_enc_file']
            key_size = request.form['key_size']
            return enc_dec(method=method, file=file_for_enc, name=name_enc_file, key="", process="enc", key_size=key_size)
        elif method == "aes_dec":
            file_for_dec = request.files['file_for_dec']
            name_dec_file = request.form['name_dec_file']
            key = request.form['key']
            return enc_dec(method=method, file=file_for_dec, name=name_dec_file, key=key, process="dec", key_size="")
        elif method == "rsa_enc":
            file_for_enc = request.files['file_for_enc']
            pub_key = request.files['pub_key']
            name_enc_file = request.form['name_enc_file']
            return enc_dec(method=method, file=file_for_enc, name=name_enc_file, key=pub_key, process="enc", key_size="")
        elif method == "rsa_dec":
            file_for_dec = request.files['file_for_dec']
            pvt_key = request.files['pvt_key']
            name_dec_file = request.form['name_dec_file']
            return enc_dec(method=method, file=file_for_dec, name=name_dec_file, key=pvt_key, process="dec", key_size="")
        elif method == "sha3":
            file_for_enc = request.files['file_for_enc']
            return enc_dec(method=method, file=file_for_enc, name="", key="", process="enc", key_size="")    
        else:
            return render_template('home.html', user=current_user)

def enc_dec(method, file, name, key, process, key_size):
    
    if process == "enc":
        file_name = file.filename
        file.save(os.path.join(UPLOAD_FOLDER + 'file_for_encryption', file_name))
        # split the absolute path and the file
        path, file = os.path.split(file_name)
        # split the filename and the image extension
        filename, ext = file.split(".")
        output_file = UPLOAD_FOLDER + "encrypted_files/" + f"{name}.{ext}"
        input_file  = UPLOAD_FOLDER + 'file_for_encryption/' + file_name
        if method == "3_des":
            padded_key = key.encode('utf-8')
            padded_key += b'\x00' * (16 - len(padded_key))
            tripDES.des_encrypt_file(input_file=input_file, output_file=output_file, key=padded_key)
        elif method == "aes" and key_size == "128":
            key = AES.encrypt_file_128(input_file, output_file)
            key = key.decode()
        elif method == "aes" and key_size == "256":
            key = AES.encrypt_file_256(input_file, output_file)
            key = key.decode()
        elif method == "rsa_enc":
            file_path = UPLOAD_FOLDER + 'file_for_encryption/' + file_name
            size = os.path.getsize(file_path)
            if size>244:
                flash('File size is more than key size! Please upload a smaller size file.')
                return render_template('rsa_enc.html', user=current_user)
            else:
                key = key.read()
                RSA.encrypt_file(key, input_file, output_file)
                key = ""
        elif method == "sha3":
            hash_value = SHA3.sha3_256(input_file)
            return render_template('display_hash.html', user= current_user, hash=hash_value)
        else:
            print()
        output_file = output_file[7:]
        return render_template('download_file.html', file_path=output_file, user= current_user, process_name= "encryption", key=key)
    elif process == "dec":
        file_name = file.filename
        file.save(os.path.join(UPLOAD_FOLDER + 'file_for_decrption', file_name))
        # split the absolute path and the file
        path, file = os.path.split(file_name)
        # split the filename and the image extension
        filename, ext = file.split(".")
        output_file = UPLOAD_FOLDER + "decrypted_files/" + f"{name}.{ext}"
        input_file  = UPLOAD_FOLDER + 'file_for_decrption/' + file_name
        if method == "3_des_dec":
            padded_key = key.encode('utf-8')
            padded_key += b'\x00' * (16 - len(padded_key))
            tripDES.des_decrypt_file(input_file=input_file, output_file=output_file, key=padded_key)
        elif method == "aes_dec" and len(key)==44:
            byte_key = bytes(key, 'utf-8')
            AES.decrypt_file_128(byte_key, input_file, output_file)
        elif method == "aes_dec" and len(key)==32:
            byte_key = bytes(key, 'utf-8')
            print(type(byte_key))
            AES.decrypt_file_256(byte_key, input_file, output_file)
        elif method == "rsa_dec":
            key = key.read()
            RSA.decrypt_file(key, input_file, output_file)
            key = ""
        output_file = output_file[7:]
        return render_template('download_file.html', file_path=output_file, user= current_user, process_name= "decryption", key=key)

    