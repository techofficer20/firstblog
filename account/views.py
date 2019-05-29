from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib import auth
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib import messages
from django.contrib.auth import update_session_auth_hash
# Create your views here.


def signup(request):
    if request.method == 'POST': # method 방식이 POST여야만 가능
        # User has info and wants an account now!
        if request.POST['password1'] == request.POST['password2']: # 비번과 확인용 비번이 같아야만 가능
            try:
                user = User.objects.get(username=request.POST['username']) # username을 입력받음
                return render(request, 'signup.html', {'error': 'Username has already been taken'}) #입력받은 username이 중복되면
            except User.DoesNotExist: #입력받은 username이 새로운 것이면
                user = User.objects.create_user( # user 생성됨..
                    username=request.POST['username'], password=request.POST['password1']) # 이름, 비밀번호 입력됨..
                auth.login(request, user)
                return redirect('/')
        else: # 비번과 확인용 비번이 같지 않으면
            return render(request, 'signup.html', {'error': 'Passwords must match'})
    else: # 단순히 호출인 경우..
        # User wants to enter info
        return render(request, 'signup.html')


def login(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = auth.authenticate(request, username=username, password=password)
        if user is not None:
            auth.login(request, user)
            return redirect('/')
        else:
            return render(request, 'login.html', {'error': 'username or password is incorrect.'})
    else:
        return render(request, 'login.html')
def logout(request):
    if request.method == 'POST':
        auth.logout(request)
        return redirect('/')
    return render(request, 'signup.html')

def changepw(request):
    if request.method == 'POST':
        form = PasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            update_session_auth_hash(request, user)  # Important!
            messages.success(request, 'Your password was successfully updated!')
            return redirect('changepw')
        else:
            messages.error(request, 'Please correct the error below.')
    else:
        form = PasswordChangeForm(request.user)
    return render(request, 'account/changepw.html', {
        'form': form
    })