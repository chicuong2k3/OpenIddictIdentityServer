window.login = async (email, password, rememberMe) => {
    const response = await fetch('/api/account/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: new URLSearchParams({
            'Email': email,
            'Password': password,
            'RememberMe': rememberMe
        })
    });

    if (!response.ok) {
        return {
            isSuccess: false,
            errorMessage: await response.text()
        }
    }

    return {
        isSuccess: true,
        errorMessage: null
    };
};

window.logout = async () => {
    const response = await fetch('/api/account/logout', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        }
    });

    if (!response.ok) {
        return false;
    }

    return true;
};