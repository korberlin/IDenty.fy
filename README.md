

# identy.fy

**identy.fy** is a powerful web application developed to bridge the gap between audio track decomposition and playlist management on Spotify. By leveraging cutting-edge technology and user-friendly design, the app provides a seamless experience for users to transform long audio files or URLs into individual tracks and subsequently create or manage playlists on Spotify.

## Overview

Developed using a stack that comprises Python, HTML, CSS, and JavaScript, **identy.fy** provides a comprehensive platform with various functionalities:

- **User Authentication**: Streamlined processes allow users to register, log in, and even reset forgotten passwords with ease.
  
- **Dashboard**: Once authenticated, users gain access to a unique dashboard, granting them the capability to upload audio files or submit URLs for track decomposition.
  
- **Playlist Management**: Within the app, users have full autonomy over their playlists. They can view, edit, or even delete their created playlists to curate their listening experience.
  
- **Spotify Integration**: A standout feature of the app, users can synchronize their Spotify account, enabling them to directly export created playlists into their Spotify accounts as private playlists.
  
- **Settings Control**: Users have the flexibility to manage their account settings, be it unlinking their Spotify account or deciding to delete their profile altogether.

## Technical Details

**identy.fy** thrives on its technological underpinnings. Key technologies employed include:

- **Flask**: The backbone of the backend framework.
  
- **SQLAlchemy**: ORM used for efficient database operations.
  
- **SQLite**: The default database, although users have the freedom to configure other options if they desire.
  
- **AUDD API**: Empowers the app's capability to decompose audio files into distinct tracks.
  
- **Spotify API**: Plays a pivotal role in playlist creation and management on the Spotify platform.

### Routes

The application consists of multiple interactive routes:

- **Login/Homepage**: Serves as the initial landing page elucidating the app's features, while also facilitating user login.
- ![Screenshot of Login/Homepage]([path_to_screenshot_for_login_page.png](https://github.com/korberlin/IDenty.fy/blob/main/identy.fy/static/ss/login.png))

- **Register**: Allows new users to join the **identy.fy** community.
- ![Screenshot of Register](path_to_screenshot_for_register_page.png)
  
- **Forgot**: An essential feature that aids users in resetting their forgotten passwords.
- ![Screenshot of Forgot](path_to_screenshot_for_forgot_page.png)
  
- **Index**: Acts as the dashboard or welcome page for users post-login.
- ![Screenshot of Index](path_to_screenshot_for_index_page.png)
  
- **Upload**: A dedicated space where users can submit long audio files either locally or via URLs.
- ![Screenshot of Upload](path_to_screenshot_for_upload_page.png)
  
- **Playlists**: Enables users to oversee previously created playlists. Additionally, they can modify playlist names, delete tracks, or even the entire playlist, and directly export playlists to their Spotify account.
- ![Screenshot of Playlists](path_to_screenshot_for_playlists_page.png)
  
- **Settings**: Offers users an array of options to enhance their app experience — from unlinking their Spotify account, altering passwords, updating email addresses, to even deleting their account.
- ![Screenshot of Settings](path_to_screenshot_for_settings_page.png)

### API Usage

**identy.fy** seamlessly integrates with two APIs:

- **AUDD**: The AUDD audio recognition API facilitates the decomposition of lengthy audio files into individual tracks. To optimize efficiency, the API settings are tuned to request decomposition at intervals of 2-3 minutes, though users can tweak these settings to be more dense, like every 12 seconds.

- **Spotify**: The application integrates with the Spotify API in two critical ways. Initially, after obtaining the decomposition data from AUDD, the app fuses the track name, artist, and album information to extract the Spotify URI of each track, which is then stored in the database. Subsequently, during playlist exportation, the app redirects users to Spotify, requesting permission to generate a token. This enhances the user experience by auto-generating tokens in the background whenever the primary token expires, thereby eliminating constant manual permissions.

## Getting Started

### Prerequisites

- Make sure Python is installed on your system.

### Installation Steps

1. Clone the repository:
   ```bash
   git clone https://github.com/korberlin/identy.fy.git
   ```

2. Move into the project directory:
   ```bash
   cd identy.fy
   ```

3. Install all required packages:
   ```bash
   pip install -r requirements.txt
   ```

4. Ensure the following environment variables are set:
   - `DATABASE_URI`: Your database URI (defaults to SQLite).
   - `FLASK_SECRET_KEY`: Secret key for your Flask app.
   - `SPOTIFY_CLIENT_ID` & `SPOTIFY_CLIENT_SECRET`: Credentials for Spotify API.
   - `API_TOKEN`: Token for the AUDD API.

5. Launch the application:
   ```bash
   flask run
   ```

## Database Models

- **User**: A model representing each registered user with fields for usernames, emails, Spotify details, and linked playlists.

- **Playlist**: Denotes a playlist made by a user, containing references to its owner and the affiliated tracks.

- **Track**: Signifies a decomposed track with details such as title, artist, album, and its associated playlist.

## Error Handling

To ensure a smooth user experience, **identy.fy** comes with a comprehensive error-handling mechanism, equipped with global error handlers and intuitive flash messages that guide users during unexpected events.

## License

**identy.fy** is licensed under the MIT License.

--- 
