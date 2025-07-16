#!/bin/bash

echo "Starting demo vulnerable web application..."

# Check if PHP is installed
if ! command -v php &> /dev/null; then
    echo "PHP is not installed. Please install PHP to run the demo."
    exit 1
fi

# Create demo_target directory if it doesn't exist
if [ ! -d "demo_target" ]; then
    mkdir -p demo_target
fi

# Start PHP built-in server
cd demo_target
php -S localhost:8080 &
SERVER_PID=$!

echo "Demo server started on http://localhost:8080"
echo "Server PID: $SERVER_PID"

# Wait a moment for server to start
sleep 2

echo ""
echo "Now you can test the tool against the demo application:"
echo "  python3 main.py --all http://localhost:8080"
echo "  python3 main.py --xss http://localhost:8080"
echo "  python3 main.py --csrf http://localhost:8080"
echo ""
echo "Press Ctrl+C to stop the demo server"

# Function to cleanup on exit
cleanup() {
    echo ""
    echo "Stopping demo server..."
    kill $SERVER_PID 2>/dev/null
    echo "Demo server stopped."
    exit 0
}

# Set trap to cleanup on script exit
trap cleanup SIGINT SIGTERM

# Keep script running
wait $SERVER_PID
