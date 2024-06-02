import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from django.contrib.auth import logout
import mysql.connector as MySQLdb
from django.shortcuts import redirect, render
from django.shortcuts import render, HttpResponse, HttpResponseRedirect
import webbrowser
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
import base64
from .utils import encrypt_text, decrypt_text
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

# database connection
db = MySQLdb.connect(
    host='localhost',
    user='root',
    password='',
    database='encryo')
c = db.cursor()

# Create your views here.
def index(request):
    return render(request, 'index.html')

def loginpg(request):
    msg = ""
    if(request.POST):
        email = request.POST.get("email")
        pwd = request.POST.get("pswd")
        s = "SELECT COUNT(*) FROM tbllogin WHERE username='"+email+"'"
        c.execute(s)
        i = c.fetchone()
        if(i[0] > 0):
            s = "SELECT * FROM tbllogin WHERE username='"+email+"'"
            c.execute(s)
            i = c.fetchone()
            if(i[1] == pwd):
                request.session['email']=email
                if(i[2] == "admin"):
                    return HttpResponseRedirect("/adminhome")
                if(i[2] == "user"):
                    return HttpResponseRedirect("/userhome")
            else:
                msg = "Incorrect Password"
        else:
            msg = "User doesn't exist"
    return render(request, 'loginpg.html',{"msg": msg})

def logout_view(request):
    logout(request)
    return redirect('index')

def register(request):
    msg = ""
    if(request.POST):
        fname = request.POST.get("txtFname")
        sname = request.POST.get("txtSname")
        email = request.POST.get("txtEmail")
        mobs = request.POST.get("txtMobs")    
        pwd = request.POST.get("txtPswd")
        s = "select count(*) from tbllogin where username='"+str(email)+"'"
        c.execute(s)
        i = c.fetchone()
        if(i[0] > 0):
            msg = "User already registered"
        else:
            s = "insert into tbluser(fname,sname,email,mobs) values('"+str(fname)+"','"+str(sname)+"','"+str(email)+"','"+str(mobs)+"')"
            print(s)
            try:
                c.execute(s)
                db.commit()
            except:
                msg = "Sorry registration error"
            else:
                s = "insert into tbllogin (username,password,utype) values('"+str(email)+"','"+str(pwd)+"','user')"
                try:
                    c.execute(s)
                    db.commit()
                except:
                    msg = "Sorry login error"
                else:
                    msg =    "Registration successfull"
    return render(request, 'register.html',{"msg": msg})

def userhome(request):
    email = request.session["email"]
    # msg = ""
    s = "SELECT * FROM tbluser WHERE email='"+str(email)+"'"
    c.execute(s)
    data = c.fetchall()
    return render(request, 'userhome.html',{"data":data})

def adminhome(request):
    try:
        email = request.session["email"]
        s = "SELECT * FROM tbluser"
        c.execute(s)
        data = c.fetchall()
        return render(request, 'adminhome.html',{"data":data})
    except:
        return HttpResponseRedirect('index')

def encrypt(request):
    return render(request, 'cipher.html')


# <--- RSAENCRYPTION --->

def rsa_key_generator(request):
    email = request.session["email"]
    key_size = int(request.GET.get('key_size'))
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')

    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    # Remove leading and trailing whitespaces
    private_pem = private_pem.strip()
    public_pem = public_pem.strip()

    # Check if the user has already stored a public key
    s = "SELECT COUNT(*) FROM tblkeys WHERE email='"+str(email)+"'"
    c.execute(s)
    count = c.fetchone()

    if count[0] > 0:
        # Update the existing public key
        c.execute("UPDATE tblkeys SET pkey=%s WHERE email=%s", (public_pem, email))
    else:
        # Insert a new record with the public key
        s = "SELECT mobs FROM tbluser WHERE email='"+str(email)+"'"
        c.execute(s)
        i = c.fetchone()
        phnv = i[0]
        c.execute("INSERT INTO tblkeys (phn, email, pkey) VALUES (%s, %s, %s)", (phnv, email, public_pem))

    db.commit()

    return render(request, 'rsakey.html', {'private_key': private_pem, 'public_key': public_pem})

def rsakey(request):
    return render(request, 'rsakey.html')

def rsahome(request):
    return render(request, 'rsahome.html')

def rsaencrypt(request):
    encrypted_message = None
    data = None
    if request.method == 'POST':
        message = request.POST.get("message")  # Use parentheses, not square brackets
        phnum = request.POST.get("mobs")  # Use parentheses, not square brackets
        s = "SELECT * FROM tblkeys WHERE phn = '" + str(phnum) + "'"
        c.execute(s)
        data = c.fetchall()
        public_key_str = request.POST.get('public_key')
        message = request.POST.get('message')

        if public_key_str and message:
            try:
                # Convert the public key string to an RSA key object
                public_key = RSA.import_key(public_key_str)

                # Encrypt the message using the public key
                cipher = PKCS1_OAEP.new(public_key)
                encrypted_message = cipher.encrypt(message.encode())

                # Encode the encrypted message in base64 for display
                encrypted_message = base64.b64encode(encrypted_message).decode()
            except Exception as e:
                # Handle exceptions, such as invalid public key format
                print(f"Error encrypting message: {e}")

    return render(request, 'rsaencrypt.html', {'encrypted_message': encrypted_message,"data": data})

def rsadecrypt(request):
    decrypted_message = None

    if request.method == 'POST':
        encrypted_message_str = request.POST.get('encrypted_message')
        print(encrypted_message_str)
        private_key_str = request.POST.get('private_key')
        print(private_key_str)
        if encrypted_message_str and private_key_str:
            try:
                # Convert the private key string to an RSA key object
                private_key = RSA.import_key(private_key_str)

                # Decode the base64-encoded encrypted message
                encrypted_message = base64.b64decode(encrypted_message_str)

                # Decrypt the message using the private key
                cipher = PKCS1_OAEP.new(private_key)
                decrypted_message = cipher.decrypt(encrypted_message).decode()
                print("Decrypted message:")
                print(decrypted_message)
            except Exception as e:
                # Handle exceptions, such as invalid private key format or decryption failure
                print(f"Error decrypting message: {e}")

    return render(request, 'rsadecrypt.html', {'decrypted_message': decrypted_message})



# <--- AESENCRYPTION --->

def aeshome(request):
    return render(request,'aes_home.html')

def aesencrypt(request):
    msg = ""
    if request.method == 'POST':
        text_to_encrypt = request.POST.get('textToEncrypt', '')
        mode = request.POST.get('mode', 'ECB')
        keysize = int(request.POST.get('keysize', '128'))
        encrypt_iv = request.POST.get('encryptiv', '') if request.POST.get('showEncryptIV') else None
        secret_key = request.POST.get('secretkey', '')
        output_format = request.POST.get('encryptOutputFormat', 'Base64')
        encrypted_output = encrypt_text(text_to_encrypt, mode, keysize, secret_key, encrypt_iv, output_format)

        return render(request,'aes_encrypt.html',{"encrypted_output": encrypted_output,"msg":msg})

    return render(request, 'aes_encrypt.html')  # Create a template for this view

def aesdecrypt(request):
    if request.method == 'POST':
        text_to_decrypt = request.POST.get('textToDecrypt', '')
        input_format = request.POST.get('decryptInputFormat', 'Base64')
        mode = request.POST.get('dmode', 'ECB')
        decrypt_iv = request.POST.get('decryptiv', '') if request.POST.get('showDecryptIV') else None
        keysize = int(request.POST.get('dkeysize', 128))
        secret_key = request.POST.get('dsecretkey', '')

        decrypted_output = decrypt_text(text_to_decrypt, mode, keysize, secret_key, decrypt_iv, input_format)

        return render(request,'aes_decrypt.html',{"decrypted_output": decrypted_output})

    return render(request, 'aes_decrypt.html')  # Create a template for this view

def viewfeedback(request):

    data = ""
    c.execute("select feedback.*,tbluser.* from feedback join tbluser on feedback.uid=tbluser.email")
    data = c.fetchall()
    print(data)
    return render(request, "adminfeedback.html", {"data": data})

def feedback(request):
    msg = ""
    uid = request.session['email']
    if(request.POST):
        msg = ""
        desc = request.POST.get('feed')
        m = "INSERT INTO `feedback`(`feedback`,`uid`)VALUES('" +str(desc)+"','"+str(uid)+"')"
        c.execute(m)
        db.commit()
        print(m)
        msg = "Message Added"

    return render(request, "feedback.html", {"msg": msg})

def extra(request):
    return render(request, 'extra.html')
