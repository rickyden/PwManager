import string
import random
import os

'''
References:

1. https://www.pythontutorial.net/python-basics/python-create-text-file/

2. https://docs.python.org/3/library/os.html

'''

def printFormattedMenuDict(title,menuDict):
    '''
        Displays items of dictionary in formated manner with "-" between key and value
    '''
    printTitle(title)

    keysMaxLen= max( [ len(item) for item in menuDict.keys()])
    valuesMaxLen= max( [ len(item) for item in menuDict.values()])
    for key, value in menuDict.items():
        print(str('{0:>'+ str(keysMaxLen + 4) + '}').format(key), '{0:^20}'.format('-'), str('{0:<'+ str(valuesMaxLen) + '}').format(value))

def printTitle(title):
    '''
        Display given string underlined
    '''
    print()
    print(title)
    print('-' * len(title))
    print()


def adminLogin():
    '''
        Implements the feature of system administrator login
    '''
    def login(username, password):
        '''
            parameters:
                username: System administrator's username
                password: System administrator's password
            output:
                Returns True if the passed credentials are correct, and return False otherwise
        '''
        adminUsername, adminPassword = '', ''
        with open('admin.txt', 'r') as file:
            adminUsername, adminPassword= eval(file.read())
            adminUsername,adminPassword = decrypt(adminUsername),decrypt(adminPassword)
        if (username == adminUsername and password == adminPassword):
            return True
        else:
            return False


    def inputCredentials():
        '''
            Returns username and password input by user via keyboard
        '''
        username = input('Username: ')
        password = input("Password: ")
        return username, password

    printTitle('Administrator Login: ')
    username, password = inputCredentials()
    while not login(username, password):
        print('Wrong username or password!')
        choice = input('Press \'y\' for trying again or press \'q\' to quit: ')

        if choice == 'y':
            username,password = inputCredentials()
        else: 
            return False
            
    # clearing screen for security purpose after updating credientials. See reference => [2]
    unnamedvariable = os.system('cls')
    return True

def accountManagement():
    def printOptions():
        '''
            Displays lists of available options of functions at 
        '''

        menuTitle= "Options:"        
        options= {
            '0':'Show Database',
            '1':'Register an account',
            '2':'Delete Registered Account',
            '3':'Update Password',
            '4':'Update admin Password',
            '5':'Back'
        }
        printFormattedMenuDict(menuTitle, options)

    if adminLogin() :
        print('\nLogin Successful!\n')
        printOptions()
        c2=-1
        while (c2 != 5):
            try:
                c2 = eval(input("select option: "))
            except:
                pass
            if (c2 == 0):
                filePath = "password.txt"
                showTable(filePath)
                input("Press any key to continue ...")
            elif (c2 == 1):
                checkApplicationPassword()
                print("\nRegister successfully!\n\n\n")
                input("Press any key to continue ...")
            elif (c2 == 2):
                deleteAccount()
                input("Press any key to continue ...")
                
            elif (c2 == 3):
                updatePassword()
                input("Press any key to continue ...")

            elif (c2 == 4):
                UpdateAdminPw()
                print("\nCredentials updated successfully!\n")
                input("Press any key to continue ...")

            elif (c2 == 5):
                #Clearing the screen after exiting the system. See reference => [2]
                unused_variable = os.system('cls')
                return
            else:
                print("Incorrect input\n\n\n")

            printOptions()

def encrypt(string):
    '''
    This function encrypt the account or password by 
    using the key "a"
    '''
    key='aaaaaaaaa'
    s= list(string[:len(string)])
    a=0
    for i in range(0,len(s)):
            s[i]=chr((ord(s[i]) + ord(key[i%8]))%127+31)
    string = "".join(s)
    return string

def decrypt(string):
    '''
    This function decrypt the account or password by 
    using the key "a"
    '''
    key='aaaaaaaaa'
    s= list(string[:len(string)])
    a=0
    for i in range(0,len(s)):
            s[i]=chr(((ord(s[i]) - ord(key[i%8]))+127-31)%127)
    string = "".join(s)
    return string


def fileToList():

    '''
        This function is used for turning file's values into the list for checking in
        fuction "checkApplicationPassword()"
    '''
    
    AccountDict = {}
    
    with open("password.txt", "r") as file:
        lines = file.readlines()

    for i in lines:
        L = i.split(",")
        AccountDict[L[0]] = L[1][:-1]

    UsernameList = list(AccountDict.keys())
    PasswordList = list(AccountDict.values())

    return AccountDict, UsernameList, PasswordList


def checkApplicationPassword():

    '''
        To check whether the username or password is already created or not
        If not, store them to a txt file called "password.txt"
    '''

    getFunctionValue = fileToList()

    Lsize = len(getFunctionValue[1]) ##get the length of the list

    UL = getFunctionValue[1] ##UL = UsernameList
    PL = getFunctionValue[2] ##PL = PasswordList

    p = -1
    while p == -1:
        p = 1
        ac = input("Enter the name of account: ")
        for i in range(0, Lsize): 
            if ac == UL[i]:
                print("The username aleady exist, try again!\n")                
                p = -1
                break
    #-------------------ban '('--------------------------
        if p==1:        
            y=list(ac)
            for j in range(0,len(y)):
                if y[j]=='(':
                    print("Do not use '(' in the input, try again!\n")
                    p = -1
                    break
    #----------------------------------------------------

    print("Options:")
    print("----------------")
    print("1  -  Design password by yourself")
    print("2  -  Design password by Password Generater")
    print("----------------")

    c = -1
    while (c != 0):
        try:
            c = eval(input("select option: "))
        except:
            pass
        if (c == 0):
            break
        elif (c == 1):
            pw = input("Enter the password: ")
            for k in range(0, Lsize):
                if pw == PL[k]:
                    print("The password aleady exist, try again!\n")
                    pw = input("Enter the password: ")
                    break
    #-------------------ban '('--------------------------
                
            a = list(pw)
            for j in range(0,len(a)):
                if a[j] == '(':
                    print("Do not use '(' in the input, try again!\n")
                    pw = input("Enter the password: ")
                    break
    #----------------------------------------------------
                else:
                    c = 0
        elif (c == 2):
            pw = randompw()
            print("Your password is", pw)
            print("Please drop down this password in a safe place!\n\n\n")
            c = 0
        else:
            print("Incorrect input")
        
    storePassword(ac, pw)


def storePassword(ac, pw):
    with open("password.txt", 'a') as file:
    #---------------encrypt-----------
        ac=encrypt(ac)
        pw=encrypt(pw)
    #---------------------------------        
        entry= ac + "," + pw
        file.write(entry+'\n')

def rewriteFile(UL,PL):
    '''
    This function rewrite the file and encrypt it
    '''
    with open("password.txt", 'w') as file:
        for i in range(0,len(UL)):
            entry = encrypt(UL[i]) + "," + encrypt(PL[i])
            file.write(entry+'\n')    

def deleteAccount():
    '''
    This function delete an account in file
    and rewrite the file so as to fill in space
    after the account is deleted
    '''
    getFunctionValue = fileToList()
    UL = getFunctionValue[1] ##UL = UsernameList
    PL = getFunctionValue[2] ##PL = PasswordList
    found=0
    pos=-1
    #-----------------Decryption-----------------
    for i in range(0,len(UL)):
        UL[i] = decrypt(UL[i])
    for i in range(0,len(PL)):
        PL[i] = decrypt(PL[i])
    #--------------------------------------------
    if UL:
        print("The list of accounts:")
        print(UL)
    else:
        print("no account stored")
        return
    ac=input("Please input the account you want to delete: ")
    for i in range(0,len(UL)):
        if UL[i] == ac:
            found=1
            pos=i
            break
    if found == 0:
        print("Cannot find the account,plsese try again!")
    else:
        UL.remove(UL[pos])
        PL.remove(PL[pos])
        rewriteFile(UL,PL)
        print("\n Delete successfully \n")

def updatePassword():
    '''
    This function search a an account
    Then update its password
    and rewrite the file 
    '''
    getFunctionValue = fileToList()
    UL = getFunctionValue[1] ##UL = UsernameList
    PL = getFunctionValue[2] ##PL = PasswordList
    Lsize = len(getFunctionValue[1]) ##get the length of the list
    found = 0
    pos = -1
    c = -1
    #-----------------Decryption-----------------
    for i in range(0,len(UL)):
        UL[i] = decrypt(UL[i])
    for i in range(0,len(PL)):
        PL[i] = decrypt(PL[i])
    #--------------------------------------------
    #if fileToList = 

    if(UL):    
        print("The list of accounts:")
        print(UL)
    else:
        print("No account stored")
        return
    ac=input("Please input the account you want to update password: ")

    for i in range(0,len(UL)):
        if UL[i] == ac:
            found = 1
            pos = i
            break
    if found == 0:
        print("Cannot find the account,plsese try again!")
    #---------------------------------------------
    if (found == 1):
        while (c != 0):
            print("Options:")
            print("----------------")
            print("1  -  Design password by yourself")
            print("2  -  Design password by Password Generater")
            print("----------------")
            while(c != 1 and c != 2):
                try:
                    c = eval(input("select option: "))
                except:
                    print("incorrect input")

            if (c == 0):
                break
            elif (c == 1):
                pw = input("Enter the password: ")
                for k in range(0, Lsize):
                    if pw == PL[k]:
                        print("The password aleady exist, try again!\n")
                        pw = input("Enter the password: ")
                        break
        #-------------------ban '('--------------------------
                    
                a = list(pw)
                for j in range(0,len(a)):
                    if a[j] == '(':
                        print("Do not use '(' in the input, try again!\n")
                        pw = input("Enter the password: ")
                        break
        #----------------------------------------------------
                    else:
                        c = 0
            elif (c == 2):
                pw = randompw()
                print("Your password is", pw)
                print("Please drop down this password in a safe place!\n\n\n")
                c = 0
            else:
                print("Incorrect input")

    if c == 0:
        PL[pos] = pw
        rewriteFile(UL,PL)
        print("\n Update successfully \n")

def UpdateAdminPw():
    '''
        Allows user to input username and password. The given credentials are updated as administrator credentials in admin.txt file
    '''
    with open('admin.txt', 'w') as file:
        print('\nPlease provide new administrator username and password:\n')
        password = ''
        username = input('username: ')
        while (len(password)<8):
            password = input('Password: ')
            if len(password)<8:
                print('Password must be greater that 8 characters!')

        entry = "\"" + encrypt(username) + "\"" + "," + "\"" + encrypt(password) +"\""
        file.write(entry)

    # clearing screen for security purpose after updating credientials
    unused_variables = os.system('cls')

def showTable(filePath):

    '''
        Input parameters:
            filepath(str): a string of relative or absolute path of a file
        Output:
            Prints the content of the file in tabular format
    '''

    with open(filePath, 'r') as file:
        lines= file.readlines()
        headers= ['Account', 'Password']
        if (len(lines)> 0 ):
            size= [len(header) for header in headers]
            for line in lines:
                i=0
                for detail in line.split(","):
                    if size[i]< len(detail):
                        size[i]= len(detail)
                    i+=1

            #printing table headers   
            print("-"*(sum(size) + 4*len(size)+5))
            i=0 
            print('|', end='')    
            for header in headers:
                print(str(" {0:" + str(size[i]+4) + "}|").format(header), end="")
                i+=1
            print('')


            print("-"*(sum(size) + 4*len(size)+5))

            for line in lines:
                i=0
                print("|", end="")
                for detail in line[:-1].split(","):

                    print(str(" {0:" + str(size[i]+4) + "}|").format(decrypt(detail)), end="")
                    i+=1
                
                print("")
                print("-"*(sum(size) + 4*len(size)+5))

        else:
                print("Data not found!")



def randompw():
    '''
    to generate a random password, the password is generated using upper case  letters, lower case letters, 
    numbers and symbol { !@#$%^&*) }. 
    it takes the length from the user input to generate a length N password
    '''
    pw = ""
    characters = list(string.ascii_letters + string.digits + "!@#$%^&*)")
    length = int(input("Enter password length: "))
    random.shuffle(characters)

    def gen():
        '''
        take N characters for the characters array and add to the password array
        then shuffle the array 
        finally return the array
        '''
        pw = []
        for i in range(length):
            pw.append(random.choice(characters))
        random.shuffle(pw)
        return pw

    password = gen()

    while(verify(password) == False):
        password = gen()

    return pw.join(password)

def count(pw):
    '''
    count the number of upper case letters, lower case letters, numbers and punctuation in an array
    return the 4 number
    '''
    bl_count = 0
    ll_count = 0
    d_count = 0
    p_count = 0
    for i in pw:
        if i in string.ascii_uppercase:
            bl_count += 1
        if i in string.ascii_lowercase:
            ll_count += 1
        if i in string.digits:
            d_count += 1
        if i in string.punctuation:
            p_count += 1
    return bl_count, ll_count, d_count, p_count

def verify(pw):
    '''
    get the number of upper case letters, lower case letters, numbers and punctuation by calling { count() }
    return { true } only if all of them are larger 1.  
    '''
    bl_count , ll_count, d_count, p_count = count(pw)
    if(bl_count == 0 or ll_count == 0 or d_count == 0 or p_count == 0 ):
        return False  
    return True        

def strength(pw):
    '''
    calculate the strength of a password

    strength meter : length, number of characters type

    if strength > 15 -> strong password
    if 7 < strength < 15 -> medium password
    if strength < 7  -> weak password
    '''
    strength, bl, ll, d, p = 0, 0, 0, 0, 0
    strpw = ""
    strpw = strpw.join(pw)
    length = len(strpw)
    if (length >= 10):
        strength += 8
    elif (length >= 9):
        strength += 4
    elif (length >= 8):
        strength += 1
    contain_ldp = verify(pw)
    
    if(contain_ldp == True):
        strength += 8
    else:
        bl, ll, d, p = count(pw)
        if ((bl > 0 and ll > 0 and d > 0) or (bl > 0 and ll > 0 and p > 0) or (bl > 0 and d > 0 and p > 0)
            or (ll > 0 and d > 0 and d > 0)):
            strength += 4
        elif ((bl > 0 and ll > 0) or (bl > 0 and d > 0) or (bl > 0 and p > 0) or (ll > 0 and d > 0)
            or (ll > 0 and p > 0) or (d > 0 and p > 0)):
            strength += 1
    
    if(strength > 15):
        print("The strength of the password is strong!\n\n\n")
    elif(strength > 7):
        print("The strength of the password is medium!\n\n\n")
    else:
        print("The strength of the password is too weak!\n\n\n")
    
    return



def main():
    #Setting up account for first-time users by creating usernama and password for system administrator
    #Checking if file exists. See reference => [1]
    if not os.path.exists('admin.txt'):
        print("\n\n\tWELCOME TO PASSWORD MANAGEMENT SYSTEM!\n\n")
        print("Now it is time to setup your account\n\n")
        UpdateAdminPw()
        print('Account setup successfully!\n')
        input("Press any key to continue...")
    #create password.txt if it do not exist
    if not os.path.exists('password.txt'):
        with open('password.txt', 'w') as f:
            print('\npassword.txt create completed')
    
    menuTitle='Program Options:'
    options= {
        '0': 'End the program',
        '1': 'User Password Management',
        '2': 'Password Strength Checker',
    }


    choice = -1
    c2 = -1
    while (choice != 0):
        printFormattedMenuDict(menuTitle, options)
        try:
            choice = eval(input("\nSelect program: "))
        except:
            pass
        if(choice == 0):
            break
        elif (choice == 1): #A choice that to show all username and password from the txt file
            accountManagement()
            input("Press any key to continue ...")

        elif (choice == 2):
            pw = input("Enter a password: ")
            strength(pw)
            input("Press any key to continue ...")

        else:
            print("Incorrect input\n\n\n")
            input("Press any key to continue ...")


if __name__ == '__main__':
    main()
