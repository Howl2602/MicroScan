from module.signin import Signin

class Modules:
    def init(self, target):
        res = Signin().signup(target)

        return res;
        
    def getJwt(self, target):
        return Signin().signin(target)