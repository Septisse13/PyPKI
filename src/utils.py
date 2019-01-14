def testType(obj, type):
    if not isinstance(obj, type):
        raise TypeError("{obj} is not a {type}".format(
                            obj=type(obj).__name__,
                            type=type.__name__))



class Observer:
    def update(observable, arg):
        '''Called when the observed object is
        modified. You call an Observable object's
        notifyObservers method to notify all the
        object's observers of the change.'''
        pass

class Observable():
    def __init__(self):
        self.obs = []
        self.changed = 0

    def addObserver(self, observer):
        if observer not in self.obs:
            self.obs.append(observer)

    def deleteObserver(self, observer):
        self.obs.remove(observer)

    def notifyObservers(self, arg = None):
        '''If 'changed' indicates that this object
        has changed, notify all its observers, then
        call clearChanged(). Each observer has its
        update() called with two arguments: this
        observable object and the generic 'arg'.'''

        # Updating is not required to be synchronized:
        for observer in self.obs:
            observer.update(arg)

    def deleteObservers(self):
        self.obs = []

    def countObservers(self):
        return len(self.obs)

    def deleteObserver(self, observer):
        for i in range(len(self.obs)):
            if self.obs[i] == observer:
                del self.obs[i]
                return
