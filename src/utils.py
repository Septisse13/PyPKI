def testType(obj, type):
    if not isinstance(obj, type):
        raise TypeError("{obj} is not a {type}".format(
                            obj=type(obj).__name__,
                            type=type.__name__))
