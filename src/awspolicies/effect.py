# Author: santiago93echevarria@gmail.com

class Effect:
    """ Parent class for types of Effect in Statement
    """
    def __repr__(self):
        return str(self.__class__.__name__)

    def __str__(self):
        return self.__repr__()


class Allow(Effect):
    """ Allow Effect for Policy Statement
    """

    def __bool__(self):
        return True


class Deny(Effect):
    """ Deny Effect for Policy Statement
    """
    def __bool__(self):
        return False


class NoEffect():
    """ Placeholder class for representing cases where action is not reached by Statement or Policy
    Note: Not a valid value for Statment's field Effect
    """

    def __bool__(self):
        return False  # Deny by default behaviour
