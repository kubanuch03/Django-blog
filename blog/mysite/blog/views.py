from importlib.resources import _

from django.conf import settings


from django.contrib.auth import authenticate, login, get_user_model, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import PasswordResetForm, SetPasswordForm, AuthenticationForm
from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.contrib.auth.views import LoginView, PasswordContextMixin, SuccessURLAllowedHostsMixin
from django.core.checks import messages
from django.core.exceptions import ValidationError
from django.urls import reverse_lazy
from django.utils.http import urlsafe_base64_decode
from django.views import View
from django.shortcuts import render, redirect, resolve_url
from django.contrib.auth.tokens import default_token_generator as \
    token_generator, default_token_generator
from django.views.generic import ListView, DetailView, CreateView, UpdateView, DeleteView, FormView, TemplateView

from .forms import ContactForm, MyForm, UserRegisterForm, UserUpdateForm, ProfileUpdateForm
from .models import Posts, Profile
from .utils import send_email_for_verify
from django.core.mail import send_mail
User = get_user_model()






def register_user(request):
    if request.method == 'POST':
        form = UserRegisterForm(request.POST)
        if form.is_valid():
            user = form.save()
            profile = Profile.objects.create(user=user)
            profile.save()
            user.save()
            email = form.cleaned_data.get('email')
            password = form.cleaned_data.get('password1')
            user = authenticate(email=email, password=password)
            send_email_for_verify(request, user,password)

            return redirect('confirm_email')
    else:
        form = UserRegisterForm()
    context = {'form': form}
    return render(request, 'registration/register.html', context)






class PostListView(ListView):
    model = Posts
    template_name = 'blog/index.html'
    context_object_name = 'posts'
    ordering = ['-date_posted']

def contact(request):
    my_form = MyForm()
    render_form = my_form.render('form/form_snippet.html')

    if request.method == 'POST':
        form = ContactForm(request.POST)
        if form.is_valid():
            subject = form.cleaned_data['subject']
            message = form.cleaned_data['message']
            sender = form.cleaned_data['sender']

            recipients = ['zazaka71@gmail.com']

            send_mail(subject, message, sender, recipients)


            return redirect('home')

    else:
        form = ContactForm()

    return render(request, 'blog/contact.html', {'form': render_form})

class PostDetailView(DetailView):
    model = Posts
    template_name = 'blog/detail.html'
    context_object_name = 'post'


class PostCreateView(LoginRequiredMixin, CreateView):
    model = Posts
    template_name = 'blog/create.html'
    fields = ['title', 'content']

    def form_valid(self, form):
        form.instance.author = self.request.user
        return super().form_valid(form)


class PostUpdateView(LoginRequiredMixin, UserPassesTestMixin, UpdateView):
    model = Posts
    template_name = 'blog/update.html'
    fields = ['title', 'content']

    def test_func(self):
        post = self.get_object()
        if self.request.user == post.author:
            return True
        return False


class PostDeleteView(LoginRequiredMixin, UserPassesTestMixin, DeleteView):
    model = Posts
    template_name = 'blog/delete.html'
    success_url = reverse_lazy('home')

    def test_func(self):
        post = self.get_object()
        if self.request.user == post.author:
            return True
        return False
# =====================Password_Reset=====================


class PasswordResetUser(PasswordContextMixin, FormView):
    email_template_name = "registration/password_reset_email.html"
    extra_email_context = None
    form_class = PasswordResetForm
    from_email = None
    html_email_template_name = None
    subject_template_name = "registration/password_reset_subject.txt"
    success_url = reverse_lazy("password_reset_done")
    template_name = "registration/password_reset_form.html"
    title = _("Password reset")
    token_generator = default_token_generator




class ResetPasswordDoneUser(PasswordContextMixin,TemplateView):

    template_name = 'registration/password_reset_done.html'
    title = _("Password reset sent")


class PasswordResetConfirimUser(PasswordContextMixin,FormView):
    template_name = 'password/password_reset_confirm.html'

    def get(self,request):
        context = {
            'form': SetPasswordForm
        }
        return render(request,self.template_name,context)


class PasswordResetCompleteUser(PasswordContextMixin,TemplateView):
    template_name = 'password/password_reset_complete.html'
    title = _("Password reset complete")

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["login_url"] = resolve_url(settings.LOGIN_URL)
        return context



#====================USER====================================

class MyLoginView(LoginView):

    form_class = AuthenticationForm


class EmailVerify(View):

    def get(self, request, uidb64, token):
        user = self.get_user(uidb64)

        if user is not None and token_generator.check_token(user, token):
            user.email_verify = True
            user.save()
            login(request, user)
            return redirect('home')
        return redirect('invalid_verify')

    @staticmethod
    def get_user(uidb64):
        try:
            # urlsafe_base64_decode() decodes to bytestring
            uid = urlsafe_base64_decode(uidb64).decode()
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError,
                User.DoesNotExist, ValidationError):
            user = None
        return user








@login_required
def profile(request):
    if request.method == 'POST':
        user_update = UserUpdateForm(request.POST, instance=request.user)
        profile_update = ProfileUpdateForm(request.POST, request.FILES, instance=request.user.profile)
        if user_update.is_valid() and profile_update.is_valid():
            user_update.save()
            profile_update.save()
            # messages.success(request, f'Your Account has been updated!')
            return redirect('profile')
    else:
        user_update = UserUpdateForm(instance=request.user)
        profile_update = ProfileUpdateForm(instance=request.user.profile)
    context = {
        'user_update': user_update,
        'profile_update': profile_update
    }
    return render(request, 'registration/profile.html', context)

class LoginUser(SuccessURLAllowedHostsMixin, FormView):

    form_class = AuthenticationForm
    template_name = 'registration/login.html'
    def get_success_url(self):
        return reverse_lazy('home')

def logout_user(request):
    logout(request)
    return redirect('login')
