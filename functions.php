<?php

declare(strict_types=1);

/**
 * Scope of the application:
 * 1. Allow guests to login to their wordpress account.
 * 2. Allow users to list published posts with pagination.
 * 3. Allow users to CRUD actions on posts.
 * 4. Allow user to log out.
 *
 * Problems that need to be addressed:
 * 1. Security and potential attacks.
 * 2. Code style.
 * 3. Potential performance issues.
 */
\add_filter('show_admin_bar', '__return_false');

\add_action('wp_ajax_nopriv_load_view', 'loadView');
\add_action('wp_ajax_load_view', 'loadView');

function loadView(): void
{
    $viewName = \filter_input(\INPUT_GET, 'view', \FILTER_SANITIZE_STRING);
    $publicViews = ['login'];
    $restrictedViews = ['add', 'dashboard', 'edit'];
    $viewPath = 'partials/' . $viewName . '.php';

    if (\in_array($viewName, $publicViews, true)) {
        require $viewPath;
        exit;
    }

    if (\in_array($viewName, $restrictedViews, true) && \is_user_logged_in()) {
        require $viewPath;
        exit;
    }
}

\add_action('wp_ajax_nopriv_login', 'login');
\add_action('wp_ajax_login', 'login');

function login(): void
{
    $password = \filter_input(\INPUT_GET, 'password', \FILTER_SANITIZE_STRING);
    $email = \filter_input(\INPUT_GET, 'email', \FILTER_SANITIZE_EMAIL);

    if (empty($email)) {
        \http_response_code(400);
        echo 'Missing email!';
        exit;
    }

    if (empty($password)) {
        \http_response_code(400);
        echo 'Missing password!';
        exit;
    }

    $user = \wp_signon(['user_login' => $email, 'user_password' => $password]);

    if (\is_wp_error($user)) {
        \http_response_code(400);
        echo $user->get_error_message();
        exit;
    }

    \http_response_code(200);
    exit;
}

\add_action('wp_ajax_post_delete', 'deletePost');

function deletePost(): void
{
    $postID = \filter_input(\INPUT_GET, 'post', \FILTER_SANITIZE_NUMBER_INT);

    if (!$postID) {
        \http_response_code(400);
        echo 'Invalid post id!';
        exit;
    }

    $delete = \wp_delete_post($postID);

    if (!$delete) {
        \http_response_code(400);
        echo 'Post cannot be delted';
        exit;
    }

    \http_response_code(200);
    exit;
}

\add_action('wp_ajax_post_insert', 'insertPost');

function insertPost(): void
{
    $postData = \filter_input(\INPUT_GET, 'post', \FILTER_SANITIZE_STRING);
    $postData = \json_decode(\htmlspecialchars_decode(\stripslashes($postData)), true);

    if (!$postData) {
        \http_response_code(400);
        echo 'Invalid post data!';
        exit;
    }

    $post = \wp_insert_post($postData);

    if (\is_wp_error($post)) {
        \http_response_code(400);
        echo $post->get_error_message();
        exit;
    }

    \http_response_code(200);
    exit;
}

\add_action('wp_ajax_nopriv_logout', 'logout');
\add_action('wp_ajax_logout', 'logout');

function logout(): void
{
    \wp_logout();

    \http_response_code(200);
    exit;
}
