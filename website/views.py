from flask import Blueprint, render_template, request
from flask_login import login_required, current_user
from .steg_advanced import encode_img, decode_file
from .server import tripDES, AES, RSA
import os
import cv2

views = Blueprint('views', __name__)

UPLOAD_FOLDER = "website/static/"

store_dict = {}

@views.route('/', methods=['GET', 'POST'])
@login_required
def home():
    return render_template("home.html", user=current_user)

@views.route('/method' , methods = ['GET', 'POST'])
def method():
    # encoded_images_list= os.listdir(UPLOAD_FOLDER + "encoded_images")
    # method = request.form['method']
    method = request.args.get('met')
    print(method,"============")
    if method == "3_des":
        return render_template('3_des.html', user=current_user)
    elif method == "3_des_dec":
        return render_template('3_des_dec.html', user=current_user)
    elif method == "aes":
        return render_template('aes.html', user=current_user)
    elif method == "aes_dec":
        return render_template('aes_dec.html', user=current_user)
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
            
    return render_template('encode.html', request_method = request_method, user=current_user)

# @views.route('/decode' , methods = ['GET', 'POST'])
# def decode():
#     request_method = request.method
#     if request_method == 'GET':
#         ini_list = request.args.get('list_files')
#         ini_list_files = ini_list.strip('][').split(', ')
#         list_files = []
#         for name_list in ini_list_files:
#             list_files.append(name_list[1:len(name_list)-1])
#     if request_method == 'POST':
#         method = request.form['method']
#         if method == "decode":
#             encoded_name = request.form['encoded_name']
#             lth_bit = int(request.form['L'])
#             s_bit = int(request.form['S'])

#             return name(method=method, file_to_encode="", image=encoded_name, lth_bit=lth_bit, s_bit=s_bit)
#     return render_template('decode.html', request_method = request_method, list_files=list_files)

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
        output_file = output_file[7:]
        return render_template('download_file.html', file_path=output_file, user= current_user, process_name= "decryption", key=key)

    elif method == "decode":
        decoded_data = decode_file(UPLOAD_FOLDER + 'encoded_images/' + image, lth_bit=lth_bit, s_bit=s_bit)
        print(decoded_data)
        final = decoded_data[7:]
        print(final)

        return render_template('decoded_file_display.html', filename=final, user= current_user)