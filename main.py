import customtkinter as tk
from customtkinter import *
from CTkMessagebox import *
import os
import sqlite3

user_act = None
check_var = 0

CHEMIN_RESSOURCE = "base_de_donner"

def getRessource(ressource):
	try:
		base_path = sys._MEIPASS
	except Exception:
		base_path = os.path.abspath(".")
	return os.path.join(base_path, CHEMIN_RESSOURCE) + "/" + ressource

key_file = getRessource("keyfile.key")

con = sqlite3.connect(getRessource("base_de_donner.db"))
cur = con.cursor()
cur.execute(""" CREATE TABLE IF NOT EXISTS 'iduser' ('user' TEXT, 'pass' TEXT)""")
con.commit()
con.close()

root = tk.CTk()
root.title("Gestionnaire de mots de passe")
root.geometry("1000x600")
#root.resizable(False, False)

def create_cipher_key():
    original_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@._-()éàè'!/,=&#{[|^ç]°=+}²<>$*ùôûîêâ;:§?µ%£ï"
    encrypted_chars = "fghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@._-()éàè'!/,=&#{[|^ç]°=+}²<>$*ùôûîêâ;:§?µ%£ïabcde"
    
    cipher_key = {}
    for i in range(len(original_chars)):
        cipher_key[original_chars[i]] = encrypted_chars[i]
    
    return cipher_key

def crypt(az):
    cipher_key = create_cipher_key()
    encrypted_message = ""
    for char in az:
        encrypted_char = cipher_key.get(char, char)
        encrypted_message += encrypted_char
    
    return encrypted_message

def decrypt(az):
    cipher_key = create_cipher_key()
    decrypted_message = ""
    for char in az:
        decrypted_char = None
        for key, value in cipher_key.items():
            if value == char:
                decrypted_char = key
                break
        if decrypted_char is not None:
            decrypted_message += decrypted_char
        else:
            decrypted_message += char
    
    return decrypted_message


class ScrollableLabelButtonFrame(tk.CTkScrollableFrame):
    def __init__(self, master, command=None, **kwargs):
        super().__init__(master, **kwargs)
        self.grid_columnconfigure(0, weight=1)

        self.command = command
        self.radiobutton_variable = tk.StringVar()
        self.label_list = []
        self.button_list = []

    def add_item(self, item, image=None):
        self.label = tk.CTkLabel(self, text=item, image=image, compound="left", padx=5, anchor="w")
        self.button = tk.CTkButton(self, text="Modifier", width=70, height=24)
        if self.command is not None:
            self.button.configure(command=lambda: self.command(item))
        
        self.label.grid(row=len(self.label_list), column=0, pady=(0, 10), sticky="w")
        self.button.grid(row=len(self.button_list), column=1, pady=(0, 10), padx=5)
        self.label_list.append(self.label)
        self.button_list.append(self.button)

    def remove_item(self, item):
        for label, button in zip(self.label_list, self.button_list):
            if item == label.cget("text"):
                label.destroy()
                button.destroy()
                self.label_list.remove(label)
                self.button_list.remove(button)
                return

class ScrollableLabelButton(tk.CTkScrollableFrame):
    def __init__(self, master, command=None, **kwargs):
        super().__init__(master, **kwargs)
        self.grid_columnconfigure(0, weight=1)

        self.command = command
        self.radiobutton_variable = tk.StringVar()
        self.label_list = []
        self.button_list = []

    def add_item(self, item, image=None):
        self.label = tk.CTkLabel(self, text=item, image=image, compound="left", padx=5, anchor="w")
        self.button = tk.CTkButton(self, text="Supprimer", width=70, height=24)
        if self.command is not None:
            self.button.configure(command=lambda: self.command(item))
        
        self.label.grid(row=len(self.label_list), column=0, pady=(0, 10), sticky="w")
        self.button.grid(row=len(self.button_list), column=1, pady=(0, 10), padx=5)
        self.label_list.append(self.label)
        self.button_list.append(self.button)

    def remove_item(self, item):
        for label, button in zip(self.label_list, self.button_list):
            if item == label.cget("text"):
                label.destroy()
                button.destroy()
                self.label_list.remove(label)
                self.button_list.remove(button)
                return

def show_all_admin():
    name_admin.grid(row = 1, column=0, pady = (125, 20), padx = 20, sticky = "e")
    passe_admin.grid(row = 2, column=0, pady = 20, padx = 20, sticky = "e")
    boutton_admin.grid(row = 3, column=0, pady = 20, padx = 20, sticky = "e")
    list_user.grid(row = 0, column = 2, sticky = "ns", padx = 20, pady = 20, ipadx = 130, ipady = 137, rowspan = 8)
    refresh_admin()

def add_admin():
    con = sqlite3.connect(getRessource("base_de_donner.db"))
    cur = con.cursor()
    cur.execute("SELECT *, oid FROM 'iduser'")
    records = cur.fetchall()
        
    for record in records:
        record1 = list(record)
        del record1[2]
        record2 = "Utilisateur : "+decrypt(record1[0])+"   Passe : "+decrypt(record1[1])
        list_user.remove_item(record2)
    
    if name_admin.get() == "":
        CTkMessagebox(title = "ERROR", message = "Utilisateur et passe doivent etre rempli")
    else:
        if passe_admin.get() == "":
            CTkMessagebox(title = "ERROR", message = "Utilisateur et passe doivent etre rempli")
        else:
            cur.execute('INSERT INTO "iduser" VALUES ("'+crypt(name_admin.get())+'", "'+crypt(passe_admin.get())+'")')
            con.commit()
            con.close()
            
            name_admin.delete(0 , END)
            name_admin.configure(placeholder_text = "Utilisateur")
            passe_admin.delete(0, END)
            passe_admin.configure(placeholder_text = "Passe")
            refresh_admin()

def remove_admin(b):
    con = sqlite3.connect(getRessource("base_de_donner.db"))
    cur = con.cursor()
    cur.execute("SELECT *, oid FROM 'iduser'")
    records = cur.fetchall()
        
    for record in records:
        record1 = list(record)
        del record1[2]
        record2 = "Utilisateur : "+decrypt(record1[0])+"   Passe : "+decrypt(record1[1])
        list_user.remove_item(record2)
        
    b = b[14:len(b)]
    pos1 = b.find("   Passe : ")
    name = b[0:pos1]
    b = b[len(name)+11:len(b)]
    passe = b

    cur.execute("DELETE from 'iduser' where user = '"+crypt(name)+"' AND pass = '"+crypt(passe)+"'")
    try:
        cur.execute("DROP TABLE '"+crypt(name)+"'")
    except:
        aazaz = 45
    
    con.commit()
    con.close()
    refresh_admin()

def refresh_admin():
    con = sqlite3.connect(getRessource("base_de_donner.db"))
    cur = con.cursor()
    cur.execute("SELECT *, oid FROM 'iduser'")
    records = cur.fetchall()
        
    for record in records:
        record1 = list(record)
        del record1[2]
        record2 = "Utilisateur : "+decrypt(record1[0])+"   Passe : "+decrypt(record1[1])
        list_user.remove_item(record2)

    for record in records:
        record1 = list(record)
        del record1[2]
        record2 = "Utilisateur : "+decrypt(record1[0])+"   Passe : "+decrypt(record1[1])
        list_user.add_item(record2)
            
    con.commit()
    con.close()

def check_box():
    global check_var
    if check_var == 0:  
        entry_password.configure(show = "")
        check_var += 1
    else:
        entry_password.configure(show = "*")
        check_var -= 1

def connexion():
    global user_act
    con = sqlite3.connect(getRessource("base_de_donner.db"))
    cur = con.cursor()
    cur.execute("SELECT *, oid FROM iduser")
    records = cur.fetchall()
    if entry_name.get() == "a" and entry_password.get() == "a":
            name.destroy()
            entry_name.destroy()
            entry_password.destroy()
            entry_password_view.destroy()
            boutton_connection.destroy()
            con.close()
            show_all_admin()
    else:
        for record in records:
            record = list(record)
            if entry_name.get() == decrypt(record[0]) and entry_password.get() == decrypt(record[1]):
                user_act = record[0]
            
                con.close()
                
                con = sqlite3.connect(getRessource("base_de_donner.db"))
                cur = con.cursor()
                cur.execute(""" CREATE TABLE IF NOT EXISTS '"""+user_act+"""' ('site' TEXT, 'pass' TEXT, 'mail' TEXT, 'other' TEXT)""")
                con.close()
                
                name.destroy()
                entry_name.destroy()
                entry_password.destroy()
                entry_password_view.destroy()
                boutton_connection.destroy()
                show_all()
            else:
                con.close()
                error_pass.configure(text = "ERROR")

def refresh():
    global user_act
    con = sqlite3.connect(getRessource("base_de_donner.db"))
    cur = con.cursor()
    cur.execute("SELECT *, oid FROM '"+user_act+"'")
    records = cur.fetchall()
        
    for record in records:
        record1 = list(record)
        del record1[4]
        if record1[2] == "":
            if record1[3] == "":
                record2 = "Site : "+decrypt(record1[0])+"   Mot de passe : "+decrypt(record1[1])
            else:
                record2 = "Site : "+decrypt(record1[0])+"   Mot de passe : "+decrypt(record1[1])+"   Autre : "+decrypt(record1[3])
        else:
            if record1[3] == "":
                record2 = "Site : "+decrypt(record1[0])+"   Mot de passe : "+decrypt(record1[1])+"   Mail : "+decrypt(record1[2])
            else:
                record2 = "Site : "+decrypt(record1[0])+"   Mot de passe : "+decrypt(record1[1])+"   Mail : "+decrypt(record1[2])+"   Autre : "+decrypt(record1[3])
        myframe.remove_item(record2)

    for record in records:
        record1 = list(record)
        del record1[4]
        if record1[2] == "":
            if record1[3] == "":
                record2 = "Site : "+decrypt(record1[0])+"   Mot de passe : "+decrypt(record1[1])
            else:
                record2 = "Site : "+decrypt(record1[0])+"   Mot de passe : "+decrypt(record1[1])+"   Autre : "+decrypt(record1[3])
        else:
            if record1[3] == "":
                record2 = "Site : "+decrypt(record1[0])+"   Mot de passe : "+decrypt(record1[1])+"   Mail : "+decrypt(record1[2])
            else:
                record2 = "Site : "+decrypt(record1[0])+"   Mot de passe : "+decrypt(record1[1])+"   Mail : "+decrypt(record1[2])+"   Autre : "+decrypt(record1[3])
        myframe.add_item(record2)
            
    con.commit()
    con.close()
            
def show_all():
    add_frame.grid(row = 0, column = 2, pady = 16, rowspan = 2, )
    modif_frame.grid(row = 2, column = 2, padx = 0, rowspan = 2, )
        
    add_site.grid(row = 1, column = 0, pady = (20, 7), padx = 20, ipadx = 0)
    add_pass.grid(row = 2, column = 0, pady = 7, padx = 20, ipadx = 0)
    add_mail.grid(row = 3, column = 0, pady = 7, padx = 20, ipadx = 0)
    add_other.grid(row = 5, column = 0, pady = 7, padx = 20, ipadx = 0)
    add.grid(row = 6, column = 0, pady = (7, 20), padx = 20, ipadx = 0)
        
    modif_site.grid(row = 1, column = 0, pady = (20, 7), padx = 20, ipadx = 0)
    modif_pass.grid(row = 2, column = 0, pady = 7, padx = 20, ipadx = 0)
    modif_mail.grid(row = 3, column = 0, pady = 7, padx = 20, ipadx = 0)
    modif_other.grid(row = 5, column = 0, pady = 7, padx = 20, ipadx = 0)
    modif.grid(row = 6, column = 0, pady = 7, padx = 20, ipadx = 0)     
    sup.grid(row = 7, column = 0, pady = (7, 20), padx = 20, ipadx = 0)
    myframe.grid(row = 1, column = 0, sticky = "ns", padx = 20, pady = 0, ipadx = 250, ipady = 113, rowspan = 8)
    rearsh.grid(row = 0, column = 0, sticky = "ew", padx = 20, pady = 20,)
    
        
    refresh()

def add_list():
    global user_act
    con = sqlite3.connect(getRessource("base_de_donner.db"))
    cur = con.cursor()
    cur.execute("SELECT *, oid FROM '"+user_act+"'")
    records = cur.fetchall()
        
    for record in records:
        record1 = list(record)
        del record1[4]
        if record1[2] == "":
            if record1[3] == "":
                record2 = "Site : "+decrypt(record1[0])+"   Mot de passe : "+decrypt(record1[1])
            else:
                record2 = "Site : "+decrypt(record1[0])+"   Mot de passe : "+decrypt(record1[1])+"   Autre : "+decrypt(record1[3])
        else:
            if record1[3] == "":
                record2 = "Site : "+decrypt(record1[0])+"   Mot de passe : "+decrypt(record1[1])+"   Mail : "+decrypt(record1[2])
            else:
                record2 = "Site : "+decrypt(record1[0])+"   Mot de passe : "+decrypt(record1[1])+"   Mail : "+decrypt(record1[2])+"   Autre : "+decrypt(record1[3])
        myframe.remove_item(record2)
        
    if add_site.get() == "":
        CTkMessagebox(title = "ERROR", message = "Site et Mot de passe doivent etre remplis")
    else:
        if add_pass.get() == "":
            CTkMessagebox(title = "ERROR", message = "Site et Mot de passe doivent etre remplis")
        else:
            cur.execute("INSERT INTO '"+user_act+"' VALUES (:site, :pass, :mail, :other)", {'site': crypt(add_site.get()), 'pass': crypt(add_pass.get()), 'mail': crypt(add_mail.get()), 'other': crypt(add_other.get())})
            
            con.commit()
            con.close()
                
            add_site.delete(0, END)
            add_site.configure(placeholder_text = "Site")
            add_pass.delete(0, END)
            add_pass.configure(placeholder_text = "Mot de passe")
            add_mail.delete(0, END)
            add_mail.configure(placeholder_text = "Mail")
            add_other.delete(0, END)
            add_other.configure(placeholder_text = "Autre")
            refresh()

def scrap(ligne):
    pos1 = ligne.find("   Mot de passe : ")
    
    ligne = ligne[7:len(ligne)]
    site = ligne[0:pos1-7]
    pos1 = ligne.find("   Mot de passe : ")
    ligne = ligne[len(site)+18:len(ligne)]
    
    pos2 = ligne.find("   Mail : ")
    if pos2 == -1:
        pos3 = ligne.find("   Autre : ")
        if pos3 == -1:
            passe = ligne[0:len(ligne)]
            a = [site, passe, "", ""]
            add_modif(a)
        else:
            pos3 = ligne.find("   Autre : ")
            passe = ligne[0:pos3]
            ligne = ligne[len(passe)+11:len(ligne)]
            other = ligne[0:len(ligne)]
            a = [site, passe, "", other]
            add_modif(a)
    elif ligne.find("   Autre : ") == -1:
        pos2 = ligne.find("   Mail : ")
        passe = ligne[0:pos2]
        ligne = ligne[len(passe)+10:len(ligne)]
        mail = ligne[0:len(ligne)]
        a = [site, passe, mail, ""]
        add_modif(a)
    else:
        pos2 = ligne.find("   Mail : ")
        passe = ligne[0:pos2]
        ligne = ligne[len(passe)+10:len(ligne)]
        pos3 = ligne.find("   Autre : ")
        mail = ligne[0:pos3]
        ligne = ligne[len(mail)+11:len(ligne)]
        other = ligne[0:len(ligne)]
        a = [site, passe, mail, other]
        add_modif(a)

def add_modif(a):
    modif_site.delete(0, END)
    modif_site.insert(0, a[0])
    modif_pass.delete(0, END)
    modif_pass.insert(0, a[1])
    modif_mail.delete(0, END)
    modif_mail.insert(0, a[2])
    modif_other.delete(0, END)
    modif_other.insert(0, a[3])
    modif_site.configure(placeholder_text = "Site")
    modif_pass.configure(placeholder_text = "Mot de passe")
    modif_mail.configure(placeholder_text = "Mail")
    modif_other.configure(placeholder_text = "Autre")
        
def sup_list():
    global user_act
    con = sqlite3.connect(getRessource("base_de_donner.db"))
    cur = con.cursor()
    cur.execute("SELECT *, oid FROM '"+user_act+"'")
    records = cur.fetchall()
        
    for record in records:
        record1 = list(record)
        del record1[4]
        if record1[2] == "":
            if record1[3] == "":
                record2 = "Site : "+decrypt(record1[0])+"   Mot de passe : "+decrypt(record1[1])
            else:
                record2 = "Site : "+decrypt(record1[0])+"   Mot de passe : "+decrypt(record1[1])+"   Autre : "+decrypt(record1[3])
        else:
            if record1[3] == "":
                record2 = "Site : "+decrypt(record1[0])+"   Mot de passe : "+decrypt(record1[1])+"   Mail : "+decrypt(record1[2])
            else:
                record2 = "Site : "+decrypt(record1[0])+"   Mot de passe : "+decrypt(record1[1])+"   Mail : "+decrypt(record1[2])+"   Autre : "+decrypt(record1[3])
        myframe.remove_item(record2)
        
    if modif_site.get() == "":
        CTkMessagebox(title = "ERROR", message = "Site et Mot de passe doivent etre remplis")
    else:
        if modif_pass.get() == "":
            CTkMessagebox(title = "ERROR", message = "Site et Mot de passe doivent etre remplis")
        elif modif_mail.get() == "":
            if modif_other.get() == "":
                cur.execute("DELETE from '"+user_act+"' where site = '"+crypt(modif_site.get())+"' AND pass = '"+crypt(modif_pass.get())+"'")
            else:
                cur.execute("DELETE from '"+user_act+"' where site = '"+crypt(modif_site.get())+"' AND pass = '"+crypt(modif_pass.get())+"' AND other = '"+crypt(modif_other.get())+"'")
        elif modif_other.get() == "":
            cur.execute("DELETE from '"+user_act+"' where site = '"+crypt(modif_site.get())+"' AND pass = '"+crypt(modif_pass.get())+"' AND mail = '"+crypt(modif_mail.get())+"'")
        else:
            cur.execute("DELETE from '"+user_act+"' where site = '"+crypt(modif_site.get())+"' AND pass = '"+crypt(modif_pass.get())+"' AND mail = '"+crypt(modif_mail.get())+"' AND other = '"+crypt(modif_other.get())+"'")
            
    con.commit()
    con.close()
    
    modif_site.delete(0, END)
    modif_site.configure(placeholder_text = "Site")
    modif_pass.delete(0, END)
    modif_pass.configure(placeholder_text = "Mot de passe")
    modif_mail.delete(0, END)
    modif_mail.configure(placeholder_text = "Mail")
    modif_other.delete(0, END)
    modif_other.configure(placeholder_text = "Autre")
    refresh()
            
def modif_list():
    global user_act
    con = sqlite3.connect(getRessource("base_de_donner.db"))
    cur = con.cursor()
        
    cur.execute("SELECT *, oid FROM '"+user_act+"'")
    records = cur.fetchall()
        
    for record in records:
        record1 = list(record)
        del record1[4]
        if record1[2] == "":
            if record1[3] == "":
                record2 = "Site : "+decrypt(record1[0])+"   Mot de passe : "+decrypt(record1[1])
            else:
                record2 = "Site : "+decrypt(record1[0])+"   Mot de passe : "+decrypt(record1[1])+"   Autre : "+decrypt(record1[3])
        else:
            if record1[3] == "":
                record2 = "Site : "+decrypt(record1[0])+"   Mot de passe : "+decrypt(record1[1])+"   Mail : "+decrypt(record1[2])
            else:
                record2 = "Site : "+decrypt(record1[0])+"   Mot de passe : "+decrypt(record1[1])+"   Mail : "+decrypt(record1[2])+"   Autre : "+decrypt(record1[3])
        myframe.remove_item(record2)
        
    cur.execute("UPDATE '"+user_act+"' SET pass = '"+crypt(modif_pass.get())+"', mail = '"+crypt(modif_mail.get())+"', other = '"+crypt(modif_other.get())+"' WHERE site = '"+crypt(modif_site.get())+"'")
        
    con.commit()
    con.close()
    refresh()

def test(aa):
    print(rearsh.get())
    print(aa)

frame = tk.CTkFrame(root)
name = tk.CTkLabel(frame, text = "Gestionnaire de mots de passe", font = (tk.CTkFont(size = 45)), text_color = "#96B1FF")
entry_name = tk.CTkEntry(frame, placeholder_text="Identifiant", width = 200, height = 30)
entry_password = tk.CTkEntry(frame, placeholder_text="Mot de passe", width = 200, height = 30, show = "*") 
entry_password_view = tk.CTkCheckBox(frame, text = "", fg_color = "#96B1FF", hover_color = "#7182B2", command = check_box)
boutton_connection = tk.CTkButton(frame, text = "Connexion", width = 200, height = 30, command = connexion)
error_pass = tk.CTkLabel(frame, text = "", text_color = "red")

frame.pack(pady=(20, 20), padx=(20, 20), fill = BOTH, expand = True)
name.grid(row = 0, column=0, padx = 200, pady = 90, columnspan = 2)
entry_name.grid(row = 1, column=0, sticky = "e")
entry_password.grid(row = 2, column=0, pady = 10, sticky = "e")
entry_password_view.grid(row = 2, column=1, padx = 2, pady = 20, sticky = "w")
boutton_connection.grid(row = 4, column=0, pady = 10, sticky = "e")
error_pass.grid(row = 3, column=0, padx = 80, sticky = "e")

rearsh = tk.CTkEntry(frame, placeholder_text = "Recherche site")
rearsh.bind(sequence="a", command=test)
myframe = ScrollableLabelButtonFrame(frame, label_text = "Mots de passe", command = scrap)

add_frame = CTkFrame(frame)
modif_frame = CTkFrame(frame)

add_site = tk.CTkEntry(add_frame, placeholder_text = "Site")
add_pass = tk.CTkEntry(add_frame, placeholder_text = "Mot de passe")
add_mail = tk.CTkEntry(add_frame, placeholder_text = "Mail")
add_other = tk.CTkEntry(add_frame, placeholder_text = "Autre")

modif_site = tk.CTkEntry(modif_frame, placeholder_text = "Site")
modif_pass = tk.CTkEntry(modif_frame, placeholder_text = "Mot de passe")
modif_mail = tk.CTkEntry(modif_frame, placeholder_text = "Mail")
modif_other = tk.CTkEntry(modif_frame, placeholder_text = "Autre")

add = tk.CTkButton(add_frame, text = "Ajouter", command = add_list)
modif = tk.CTkButton(modif_frame, text = "Modifier", command = modif_list)
sup = tk.CTkButton(modif_frame, text = "Supprimer", command = sup_list)

list_user = ScrollableLabelButton(frame, label_text = "Utilisateurs", command = remove_admin)
name_admin = tk.CTkEntry(frame, placeholder_text="Name", width = 400, height = 60)
passe_admin = tk.CTkEntry(frame, placeholder_text="Passe", width = 400, height = 60)
boutton_admin = tk.CTkButton(frame, text = "Ajouter", width = 400, height = 60, command = add_admin)

root.mainloop()