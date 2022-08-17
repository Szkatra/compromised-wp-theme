const load_view = (view, args = {}) => {
  fetch('/wp-admin/admin-ajax.php?action=load_view&view=' + view +'&'+ new URLSearchParams(args), {method: 'GET'})
      .then((response) => response.text())
      .then((response) => (
          document.getElementById('app').innerHTML = response));
}

const login = () => {
  event.preventDefault();

  const form = document.getElementById('login-form');
  const error_wrapper = document.getElementById('response-error');
  const email = form.querySelector('#email');
  //console.log(email);

  const password = form.querySelector('#password');

  error_wrapper.classList.add('d-none')


  fetch('/wp-admin/admin-ajax.php?action=login&email=' + email.value + '&password=' + password.value, {method: 'GET'})
      .then(async (response) => {
        if(response.status !== 200) {
          // console.log(await response.text())
          error_wrapper.classList.remove('d-none')
          error_wrapper.innerHTML = await response.text()
          return;
        }

        load_view('dashboard')
      })
  .catch((error) => {
    console.log(error)
    error_wrapper.classList.remove('d-none')
    error_wrapper.innerHTML = error
  })
}

function deletePost(event, post_id) {
  event.preventDefault();
  const error_wrapper = document.getElementById('response-error');
  error_wrapper.classList.add('d-none')

  fetch('/wp-admin/admin-ajax.php?action=post_delete&post=' + post_id, {method: 'GET'})
      .then(async (resposnse) => {
        if(resposnse.status !== 200) {
        error_wrapper.classList.remove('d-none')
          error_wrapper.innerHTML = await resposnse.text()
          return;
        }

        load_view('dashboard')
      })
      .catch((error) => {
        console.log(error)
        error_wrapper.classList.remove('d-none')
        error_wrapper.innerHTML = error
      })
}

const logout = () => {
  event.preventDefault();

  fetch('/wp-admin/admin-ajax.php?action=logout', {method: 'GET'})
      .then(async (resposnse) => {
        if(resposnse.status !== 200) {
          // console.log(await resposnse.text())

          return;
        }

        load_view('login')
      })
      .catch((error) => {
        console.log(error)

      })
}

const insertPost = () => {
  event.preventDefault();

  const form = document.getElementById('edit-form');
  const from_data = new FormData(form)
  //console.log(email);

  const password = form.querySelector('#password');

  const error_wrapper = document.getElementById('response-error');
  error_wrapper.classList.add('d-none')


  fetch('/wp-admin/admin-ajax.php?action=post_insert&post=' + JSON.stringify(Object.fromEntries(from_data)), {method: 'GET'})
      .then(async (resposnse) => {
        if(resposnse.status !== 200) {
          // console.log(await resposnse.text())
          error_wrapper.classList.remove('d-none')
          error_wrapper.innerHTML = await resposnse.text()
          return;
        }

        load_view('dashboard')
      })
      .catch((error) => {
        console.log(error)
        error_wrapper.classList.remove('d-none')
        error_wrapper.innerHTML = error
      })
}