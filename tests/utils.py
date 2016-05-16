import random
import string


def generate_rand_string(length=12, charset=string.ascii_lowercase):
    """ Generate a random string
    :param length: length of string to generate
    :param charset: allow caller to control charset
    :return: generated string
    """
    return ''.join(random.choice(charset) for _ in range(length))
