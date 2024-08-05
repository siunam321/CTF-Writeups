<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TFC Frontend</title>
    <style>
        body {
            background-color: #f9f4e9;
            font-family: Arial, sans-serif;
            color: #333;
            margin: 0;
            padding: 0;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            height: 100vh;
        }

        .container {
            text-align: center;
        }

        .header {
            font-size: 2em;
            color: #f06292; /* matching the TFC logo */
            margin-bottom: 20px;
        }

        .form-container {
            background-color: #fff;
            border-radius: 8px;
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
            padding: 20px;
            width: 300px;
        }

        .form-group {
            margin-bottom: 15px;
        }

        .form-group label {
            display: block;
            margin-bottom: 5px;
            color: #333;
        }

        .form-group input[type="text"] {
            width: 100%;
            padding: 8px;
            border: 1px solid #ccc;
            border-radius: 4px;
        }

        .form-group button {
            width: 100%;
            padding: 10px;
            background-color: #f06292;
            border: none;
            border-radius: 4px;
            color: #fff;
            font-size: 1em;
            cursor: pointer;
        }

        .form-group button:hover {
            background-color: #e91e63;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">TFC Content Fetcher </div>
        <div class="form-container">
            <form method="get">
                <div class="form-group">
                    <label for="url">Enter URL:</label>
                    <input type="text" id="url" name="url" required>
                </div>
                <div class="form-group">
                    <button type="submit">Fetch Content</button>
                </div>
            </form>
        </div>
    </div>

    <?php

    function isAllowedIP($url, $allowedHost) {
        $parsedUrl = parse_url($url);
        
        if (!$parsedUrl || !isset($parsedUrl['host'])) {
            return false;
        }
        
        return $parsedUrl['host'] === $allowedHost;
    }

    function fetchContent($url) {
        $context = stream_context_create([
            'http' => [
                'timeout' => 5 // Timeout in seconds
            ]
        ]);

        $content = @file_get_contents($url, false, $context);
        if ($content === FALSE) {
            $error = error_get_last();
            throw new Exception("Unable to fetch content from the URL. Error: " . $error['message']);
        }
        return base64_decode($content);
    }

    if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['url'])) {
        $url = $_GET['url'];
        $allowedIP = 'localhost';
        
        if (isAllowedIP($url, $allowedIP)) {
            $content = fetchContent($url);
            // file upload removed due to security issues
            if ($content) {
                $command = 'echo ' . $content . ' | base64 > /tmp/' . date('YmdHis') . '.tfc';
                exec($command . ' > /dev/null 2>&1');
                // this should fix it
            }
        }
    }
    ?>
</body>
</html>
