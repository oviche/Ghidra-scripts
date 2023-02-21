# Decrypt Strings and remove decryption function from decompiler
#
# @category oviche.scripts
#

# Import libraries from Ghidra that will be available to use. You can navigate any
# of the packages documented in https://ghidra.re/ghidra_docs/api/index.html and
# import the types and members here using lines similar to below.

from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.util import DefinedDataIterator
from javax.crypto import Cipher;
from javax.crypto.spec import SecretKeySpec,IvParameterSpec
from java.lang import String,Integer
from java.util import Base64 
import jarray


def getDefinedStrings():
   count =-1;
   definedStrs = []
   for defStr in DefinedDataIterator.definedStrings(currentProgram):
       if(count > -1):
        definedStrs.append(defStr)
       count+=1	
   return definedStrs


def getDataAsList(bytesArray):
        data= jarray.zeros(len(bytesArray)+2, "b")
        data[0]= Integer(len(bytesArray)).byteValue()  
        
        for i in range(0,len(bytesArray)):
              data[i+1]=bytesArray[i]
	
        data[len(bytesArray)+1]=0
	return data  
        
              				  


def DecryptString(string):
   
   key = String("sosi_sosison____")
   keyBytes = key.getBytes("utf-8")
   secretKey =  SecretKeySpec(keyBytes, "aes");
   cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
   encodedString= String(string)
   decodedStrs = String(Base64.getDecoder().decode(encodedString)).split("::")
   IV = decodedStrs[1]
   encStr = decodedStrs[0]
   cipher.init(Cipher.DECRYPT_MODE, secretKey, IvParameterSpec(Base64.getDecoder().decode(IV)))
   plainTextBytes = cipher.doFinal(Base64.getDecoder().decode(encStr));

   return getDataAsList(plainTextBytes)
   

def patch(address, bytesToWrite):
   setBytes(address,bytesToWrite)



def getEncStr(address, definedStrs):
    
    instruction = getInstructionBefore(address)
    if(instruction == None):
       return None,None	  

    mnemonic= instruction.getMnemonicString()
    	
    if(mnemonic == None or mnemonic != "const_string"):
	    return None,None

	
    operand = int(instruction.toString().split(",")[1],16)
    
    encStr=""	
    strAddress = definedStrs[operand].getMinAddress()
    #print(strAddress.toString())	
 
    for byte in definedStrs[operand].getBytes():
      if(byte == 0):
           continue
      encStr+=chr(byte)	
        
    return encStr , strAddress
   



definedStrs = getDefinedStrings()
decryFunAdd = toAddr(0x500bd9e8)
xrefs = getReferencesTo(decryFunAdd)
map = dict()


for ref in xrefs:
   address = ref.getFromAddress()
   #print(address) 
   if(address):
    encStr, strAddress = getEncStr(address,definedStrs)
    if(encStr!="" and encStr!= None):
       map[strAddress]= encStr  




for address in map.keys(): # decrypt strings
  DecryptedData = DecryptString(map[address])
  addressToPatch = toAddr(address.subtract(toAddr(1)))
  patch(addressToPatch,DecryptedData)
  

for ref in xrefs: # remove the decryption function from the decompiler
   
   address = ref.getFromAddress()
   if(address):
      instruction = getInstructionAt(address)
      if(instruction):
        mnemonic= instruction.getMnemonicString()
	if(mnemonic and mnemonic == "invoke_static"):
            print(address)
            addressAfter = address.add(6)
            removeInstructionAt(address)
            removeInstructionAt(addressAfter)
            patch(address,jarray.zeros(6, "b"))
            patch(addressAfter, jarray.zeros(2, "b"))

#toAddr(0x50088de0)



print("....................done......................")










