# -*- coding: utf-8 -*-
import inspect

from django.conf import settings
from django.contrib.contenttypes.models import ContentType
from django.contrib.auth.models import User, AnonymousUser
from django.utils.importlib import import_module

from models import RulePermission
from exceptions import NotBooleanPermission
from exceptions import NonexistentFieldName
from exceptions import NonexistentPermission
from exceptions import RulesError


class ObjectPermissionBackend(object):
    supports_object_permissions = True
    supports_anonymous_user = True
    supports_inactive_user = True

    def authenticate(self, username, password):
        return None

    def get_all_permissions(self, user_obj, obj=None, only_module=None):
        #Does not check object permissions
        if user_obj.is_anonymous():
            return set()
        ret = set()
        if obj is not None:
            return set() #Would take too long
        f = {}
        if only_module:
            f['codename__contains'] = '%s.'%(only_module).lower()
        for rp in RulePermission.objects.filter(**f):
            if self.has_perm(user_obj, rp.codename, obj):
                ret.add(rp.codename)
        return ret


    def has_module_perms(self, user_obj, app_label):
        """
        Returns True if user_obj has any permissions in the given app_label. Used for admin.
        """
        if not user_obj.is_active:
            return False
        for perm in self.get_all_permissions(user_obj, only_module=app_label):
            if perm[:perm.index('.')] == app_label:
                return True
        return False

    def has_perm(self, user_obj, perm, obj=None):
        """
        This method checks if the user_obj has perm on obj. Returns True or False
        Looks for the rule with the code_name = perm and the content_type of the obj
        If it exists returns the value of obj.field_name or obj.field_name() in case
        the field is a method.
        """
        if not user_obj.is_authenticated():
            user_obj = User.objects.get(pk=settings.ANONYMOUS_USER_ID)

        # Centralized authorizations
        # You need to define a module in settings.CENTRAL_AUTHORIZATIONS that has a
        # central_authorizations function inside
        if hasattr(settings, 'CENTRAL_AUTHORIZATIONS'):
            module = getattr(settings, 'CENTRAL_AUTHORIZATIONS')

            try:
                mod = import_module(module)
            except ImportError, e:
                raise RulesError('Error importing central authorizations module %s: "%s"' % (module, e))

            try:
                central_authorizations = getattr(mod, 'central_authorizations')
            except AttributeError:
                raise RulesError('Error module %s does not have a central_authorization function"' % (module))

            try:
                is_authorized = central_authorizations(user_obj, perm)
                # If the value returned is a boolean we pass it up and stop checking
                # If not, we continue checking
                if isinstance(is_authorized, bool):
                    return is_authorized

            except TypeError:
                raise RulesError('central_authorizations should receive 2 parameters: (user_obj, perm)')

        # Note:
        # is_active and is_superuser are checked by default in django.contrib.auth.models
        # lines from 301-306 in Django 1.2.3
        # If this checks dissapear in mainstream, tests will fail, so we won't double check them :)
        if not obj:
            try:
                rule = RulePermission.objects.get(codename = perm) #Only a single instance allowed here
                rule.field_name = rule.field_name + "_any"
                ctype = rule.content_type
            except (RulePermission.DoesNotExist, RulePermission.MultipleObjectsReturned) as e:
                return False
        else:
            ctype = ContentType.objects.get_for_model(obj)

            # We get the rule data and return the value of that rule
            try:
                rule = RulePermission.objects.get(codename = perm, content_type = ctype)
            except RulePermission.DoesNotExist:
                return False

        bound_field = None
        try:
            if obj is None:
                klass = rule.content_type.model_class()
                bound_field = getattr(klass, rule.field_name)
            else:
                bound_field = getattr(obj, rule.field_name)
        except AttributeError:
            if obj is None:
                return False #backcompat
            raise NonexistentFieldName("Field_name %s from rule %s does not longer exist in model %s. \
                                        The rule is obsolete!", (rule.field_name, rule.codename, rule.content_type.model))

        if not isinstance(bound_field, bool) and not callable(bound_field):
            raise NotBooleanPermission("Attribute %s from model %s on rule %s does not return a boolean value",
                                        (rule.field_name, rule.content_type.model, rule.codename))

        if not callable(bound_field):
            is_authorized = bound_field
        else:
            # Otherwise it is a callabe bound_field
            # Let's see if we pass or not user_obj as a parameter
            if (len(inspect.getargspec(bound_field)[0]) == 2):
                is_authorized = bound_field(user_obj)
            else:
                is_authorized = bound_field()

            if not isinstance(is_authorized, bool):
                raise NotBooleanPermission("Callable %s from model %s on rule %s does not return a boolean value",
                                            (rule.field_name, rule.content_type.model, rule.codename))

        return is_authorized
